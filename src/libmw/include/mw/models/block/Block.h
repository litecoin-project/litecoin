#pragma once

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <serialize.h>
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
    Block(const mw::Header::CPtr& pHeader, mw::TxBody body)
        : m_pHeader(pHeader), m_body(std::move(body)) { }
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
    const mw::TxBody& GetTxBody() const noexcept { return m_body; }

    const std::vector<mw::Input>& GetInputs() const noexcept { return m_body.GetInputs(); }
    const std::vector<mw::Output>& GetOutputs() const noexcept { return m_body.GetOutputs(); }
    const std::vector<mw::Kernel>& GetKernels() const noexcept { return m_body.GetKernels(); }

    int32_t GetHeight() const noexcept { return m_pHeader->GetHeight(); }
    const BlindingFactor& GetKernelOffset() const noexcept { return m_pHeader->GetKernelOffset(); }
    const BlindingFactor& GetStealthOffset() const noexcept { return m_pHeader->GetStealthOffset(); }

    std::optional<CAmount> GetTotalFee() const noexcept { return m_body.GetTotalFee(); }
    std::vector<PegInCoin> GetPegIns() const noexcept { return m_body.GetPegIns(); }
    std::optional<CAmount> GetPegInAmount() const noexcept { return m_body.GetPegInAmount(); }
    std::vector<PegOutCoin> GetPegOuts() const noexcept { return m_body.GetPegOuts(); }
    std::optional<CAmount> GetSupplyChange() const noexcept { return m_body.GetSupplyChange(); }

    //
    // Serialization/Deserialization
    //
    IMPL_SERIALIZABLE(Block, obj)
    {
        READWRITE(obj.m_pHeader, obj.m_body);
    }

    //
    // Traits
    //
    const mw::Hash& GetHash() const noexcept final { return m_pHeader->GetHash(); }
    std::string Format() const final { return "Block(" + GetHash().ToHex() + ")"; }

    //
    // Context-free validation of the block.
    // Returns std::nullopt when valid, or the specific consensus error.
    //
    [[nodiscard]] std::optional<EConsensusError> Validate() const noexcept;

private:
    mw::Header::CPtr m_pHeader;
    mw::TxBody m_body;
};

class MutBlock
{
public:
    //
    // Constructors
    //
    MutBlock() = default;
    MutBlock(const Block::CPtr& pBlock)
        : m_header(pBlock->GetHeader()),
          m_inputs(pBlock->GetInputs()),
          m_outputs(pBlock->GetOutputs()),
          m_kernels(pBlock->GetKernels()) {}

    MutBlock& SetInputs(std::vector<mw::Input> inputs) noexcept
    {
        m_inputs = std::move(inputs);
        return *this;
    }

    MutBlock& SetOutputs(std::vector<mw::Output> outputs) noexcept
    {
        m_outputs = std::move(outputs);
        return *this;
    }

    MutBlock& SetKernels(std::vector<mw::Kernel> kernels) noexcept
    {
        m_kernels = std::move(kernels);
        return *this;
    }

    mw::Block::CPtr Build() const
    {
        return std::make_shared<mw::Block>(
            m_header.Build(),
            mw::TxBody(m_inputs, m_outputs, m_kernels)
        );
    }

private:
    MutHeader m_header;
    std::vector<mw::Input> m_inputs;
    std::vector<mw::Output> m_outputs;
    std::vector<mw::Kernel> m_kernels;
};

END_NAMESPACE
