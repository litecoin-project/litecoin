#pragma once

#include <mw/common/Macros.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <mw/traits/Hashable.h>
#include <mw/traits/Serializable.h>
#include <mw/traits/Printable.h>
#include <algorithm>

MW_NAMESPACE

class Block final :
    public Traits::IPrintable,
    public Traits::ISerializable,
    public Traits::IHashable
{
public:
    using Ptr = std::shared_ptr<Block>;
    using CPtr = std::shared_ptr<const Block>;

    //
    // Constructors
    //
    Block(const mw::Header::CPtr& pHeader, TxBody&& body)
        : m_pHeader(pHeader), m_body(std::move(body)), m_validated(false) { }
    Block(const mw::Header::CPtr& pHeader, const TxBody& body)
        : m_pHeader(pHeader), m_body(body), m_validated(false) { }
    Block(const Block& other) = default;
    Block(Block&& other) noexcept = default;
    Block() = default;

    //
    // Operators
    //
    Block& operator=(const Block& other) = default;
    Block& operator=(Block&& other) noexcept = default;

    //
    // Getters
    //
    const mw::Header::CPtr& GetHeader() const noexcept { return m_pHeader; }
    const TxBody& GetTxBody() const noexcept { return m_body; }

    const std::vector<Input>& GetInputs() const noexcept { return m_body.GetInputs(); }
    const std::vector<Output>& GetOutputs() const noexcept { return m_body.GetOutputs(); }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_body.GetKernels(); }

    uint64_t GetHeight() const noexcept { return m_pHeader->GetHeight(); }
    const BlindingFactor& GetKernelOffset() const noexcept { return m_pHeader->GetKernelOffset(); }
    const BlindingFactor& GetOwnerOffset() const noexcept { return m_pHeader->GetOwnerOffset(); }

    uint64_t GetTotalFee() const noexcept { return m_body.GetTotalFee(); }
    std::vector<PegInCoin> GetPegIns() const noexcept { return m_body.GetPegIns(); }
    uint64_t GetPegInAmount() const noexcept { return m_body.GetPegInAmount(); }
    std::vector<PegOutCoin> GetPegOuts() const noexcept { return m_body.GetPegOuts(); }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        assert(m_pHeader != nullptr);
        return serializer.Append(m_pHeader).Append(m_body);
    }

    static Block Deserialize(Deserializer& deserializer)
    {
        mw::Header::CPtr pHeader = std::make_shared<mw::Header>(mw::Header::Deserialize(deserializer));
        TxBody body = TxBody::Deserialize(deserializer);
        return Block{ pHeader, std::move(body) };
    }

    //
    // Traits
    //
    mw::Hash GetHash() const noexcept final { return m_pHeader->GetHash(); }
    std::string Format() const final { return GetHash().ToHex(); }

    //
    // Context-free validation of the block.
    //
    void Validate() const;

    bool WasValidated() const noexcept { return m_validated; }
    void MarkAsValidated() noexcept { m_validated = true; }

private:
    mw::Header::CPtr m_pHeader;
    TxBody m_body;
    bool m_validated;
};

END_NAMESPACE