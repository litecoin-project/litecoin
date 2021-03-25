#pragma once

// Copyright (c) 2018-2019 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/crypto/Crypto.h>
#include <mw/models/crypto/Hash.h>
#include <mw/models/crypto/BigInteger.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <mw/models/tx/TxBody.h>
#include <mw/traits/Printable.h>
#include <mw/traits/Serializable.h>
#include <mw/traits/Hashable.h>

#include <memory>
#include <vector>

MW_NAMESPACE

////////////////////////////////////////
// TRANSACTION - Represents a transaction or merged transactions before they've been included in a block.
////////////////////////////////////////
class Transaction :
    public Traits::IPrintable,
    public Traits::ISerializable,
    public Traits::IHashable
{
public:
    using CPtr = std::shared_ptr<const Transaction>;

    //
    // Constructors
    //
    Transaction(BlindingFactor&& kernel_offset, BlindingFactor&& owner_offset, TxBody&& body)
        : m_kernelOffset(std::move(kernel_offset)), m_ownerOffset(std::move(owner_offset)), m_body(std::move(body))
    {
        m_hash = Hashed(*this);
    }
    Transaction(const BlindingFactor& kernel_offset, const BlindingFactor& owner_offset, const TxBody& body)
        : Transaction(BlindingFactor(kernel_offset), BlindingFactor(owner_offset), TxBody(body)) { }
    Transaction(const Transaction& transaction) = default;
    Transaction(Transaction&& transaction) noexcept = default;
    Transaction() = default;

    //
    // Factory
    //
    static mw::Transaction::CPtr Create(
        BlindingFactor kernel_offset,
        BlindingFactor owner_offset,
        std::vector<Input> inputs,
        std::vector<Output> outputs,
        std::vector<Kernel> kernels,
        std::vector<SignedMessage> owner_sigs)
    {
        std::sort(inputs.begin(), inputs.end(), SortByCommitment);
        std::sort(outputs.begin(), outputs.end(), SortByCommitment);
        std::sort(kernels.begin(), kernels.end(), KernelSort);
        std::sort(owner_sigs.begin(), owner_sigs.end(), SortByHash);

        return std::make_shared<mw::Transaction>(
            std::move(kernel_offset),
            std::move(owner_offset),
            TxBody{
                std::move(inputs),
                std::move(outputs),
                std::move(kernels),
                std::move(owner_sigs)
            }
        );
    }

    //
    // Destructor
    //
    virtual ~Transaction() = default;

    //
    // Operators
    //
    Transaction& operator=(const Transaction& transaction) = default;
    Transaction& operator=(Transaction&& transaction) noexcept = default;
    bool operator<(const Transaction& transaction) const noexcept { return GetHash() < transaction.GetHash(); }
    bool operator==(const Transaction& transaction) const noexcept { return GetHash() == transaction.GetHash(); }
    bool operator!=(const Transaction& transaction) const noexcept { return GetHash() != transaction.GetHash(); }

    //
    // Getters
    //
    const BlindingFactor& GetKernelOffset() const noexcept { return m_kernelOffset; }
    const BlindingFactor& GetOwnerOffset() const noexcept { return m_ownerOffset; }
    const TxBody& GetBody() const noexcept { return m_body; }
    const std::vector<Input>& GetInputs() const noexcept { return m_body.GetInputs(); }
    const std::vector<Output>& GetOutputs() const noexcept { return m_body.GetOutputs(); }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_body.GetKernels(); }
    const std::vector<SignedMessage>& GetOwnerSigs() const noexcept { return m_body.GetOwnerSigs(); }
    uint64_t GetTotalFee() const noexcept { return m_body.GetTotalFee(); }

    std::vector<Commitment> GetKernelCommits() const noexcept { return m_body.GetKernelCommits(); }
    std::vector<Commitment> GetInputCommits() const noexcept { return m_body.GetInputCommits(); }
    std::vector<Commitment> GetOutputCommits() const noexcept { return m_body.GetOutputCommits(); }
    std::vector<PegInCoin> GetPegIns() const noexcept { return m_body.GetPegIns(); }
    std::vector<Output> GetPegInOutputs() const noexcept { return m_body.GetPegInOutputs(); }
    uint64_t GetPegInAmount() const noexcept { return m_body.GetPegInAmount(); }
    std::vector<PegOutCoin> GetPegOuts() const noexcept { return m_body.GetPegOuts(); }
    int64_t GetSupplyChange() const noexcept { return m_body.GetSupplyChange(); }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer
            .Append(m_kernelOffset)
            .Append(m_ownerOffset)
            .Append(m_body);
    }

    static Transaction Deserialize(Deserializer& deserializer)
    {
        BlindingFactor kernel_offset = BlindingFactor::Deserialize(deserializer);
        BlindingFactor owner_offset = BlindingFactor::Deserialize(deserializer);
        TxBody body = TxBody::Deserialize(deserializer);
        return Transaction(std::move(kernel_offset), std::move(owner_offset), std::move(body));
    }

    //
    // Traits
    //
    std::string Format() const final { return GetHash().Format(); }
    mw::Hash GetHash() const noexcept final { return m_hash; }

    void Validate() const;

private:
    // The kernel "offset" k2 excess is k1G after splitting the key k = k1 + k2.
    BlindingFactor m_kernelOffset;

    BlindingFactor m_ownerOffset;

    // The transaction body.
    TxBody m_body;

    mutable mw::Hash m_hash;
};

END_NAMESPACE