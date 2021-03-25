#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Logger.h>
#include <mw/traits/Serializable.h>
#include <mw/models/crypto/BigInteger.h>
#include <mw/models/crypto/SignedMessage.h>
#include <mw/models/tx/Input.h>
#include <mw/models/tx/Output.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Schnorr.h>

#include <memory>
#include <vector>

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
    TxBody(std::vector<Input>&& inputs, std::vector<Output>&& outputs, std::vector<Kernel>&& kernels, std::vector<SignedMessage>&& ownerSigs)
        : m_inputs(std::move(inputs)), m_outputs(std::move(outputs)), m_kernels(std::move(kernels)), m_ownerSigs(std::move(ownerSigs)) { }
    TxBody(const std::vector<Input>& inputs, const std::vector<Output>& outputs, const std::vector<Kernel>& kernels, const std::vector<SignedMessage>& ownerSigs)
        : m_inputs(inputs), m_outputs(outputs), m_kernels(kernels), m_ownerSigs(ownerSigs) { }
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
            m_kernels == rhs.m_kernels &&
            m_ownerSigs == rhs.m_ownerSigs;
    }

    //
    // Getters
    //
    const std::vector<Input>& GetInputs() const noexcept { return m_inputs; }
    const std::vector<Output>& GetOutputs() const noexcept { return m_outputs; }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_kernels; }
    const std::vector<SignedMessage>& GetOwnerSigs() const noexcept { return m_ownerSigs; }

    std::vector<Commitment> GetKernelCommits() const noexcept { return Commitments::From(m_kernels); }
    std::vector<Commitment> GetInputCommits() const noexcept { return Commitments::From(m_inputs); }
    std::vector<Commitment> GetOutputCommits() const noexcept { return Commitments::From(m_outputs); }

    std::vector<PegInCoin> GetPegIns() const noexcept;
    std::vector<Output> GetPegInOutputs() const noexcept;
    uint64_t GetPegInAmount() const noexcept;
    std::vector<PegOutCoin> GetPegOuts() const noexcept;
    uint64_t GetTotalFee() const noexcept;
    int64_t GetSupplyChange() const noexcept;

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final;
    static TxBody Deserialize(Deserializer& deserializer);

    void Validate() const;

private:
    // List of inputs spent by the transaction.
    std::vector<Input> m_inputs;

    // List of outputs the transaction produces.
    std::vector<Output> m_outputs;

    // List of kernels that make up this transaction.
    std::vector<Kernel> m_kernels;

    // The owner offset can be split into a raw private key diff & a pubkey/sig version.
    std::vector<SignedMessage> m_ownerSigs;
};