#pragma once

#include <mw/common/Macros.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/UTXO.h>
#include <mw/traits/Serializable.h>

MW_NAMESPACE

class BlockUndo final : public Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const BlockUndo>;

    //
    // Constructors
    //
    BlockUndo(const mw::Header::CPtr& pPrevHeader, std::vector<UTXO>&& coinsSpent, std::vector<Commitment>&& coinsAdded)
        : m_pPrevHeader(pPrevHeader), m_coinsSpent(std::move(coinsSpent)), m_coinsAdded(std::move(coinsAdded)) { }
    BlockUndo(const BlockUndo& other) = default;
    BlockUndo(BlockUndo&& other) noexcept = default;
    BlockUndo() = default;

    //
    // Operators
    //
    BlockUndo& operator=(const BlockUndo& other) = default;
    BlockUndo& operator=(BlockUndo&& other) noexcept = default;

    //
    // Getters
    //
    const mw::Header::CPtr& GetPreviousHeader() const noexcept { return m_pPrevHeader; }
    const std::vector<UTXO>& GetCoinsSpent() const noexcept { return m_coinsSpent; }
    const std::vector<Commitment>& GetCoinsAdded() const noexcept { return m_coinsAdded; }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        if (m_pPrevHeader != nullptr) {
            serializer.Append<uint8_t>(1).Append(m_pPrevHeader);
        } else {
            serializer.Append<uint8_t>(0);
        }

        return serializer.AppendVec(m_coinsSpent).AppendVec(m_coinsAdded);
    }

    static BlockUndo Deserialize(Deserializer& deserializer)
    {
        mw::Header::CPtr pPrevHeader = nullptr;
        const bool has_previous = deserializer.Read<uint8_t>() == 1;
        if (has_previous) {
            pPrevHeader = std::make_shared<mw::Header>(mw::Header::Deserialize(deserializer));
        }

        std::vector<UTXO> coinsSpent = deserializer.ReadVec<UTXO>();
        std::vector<Commitment> coinsAdded = deserializer.ReadVec<Commitment>();

        return BlockUndo{ pPrevHeader, std::move(coinsSpent), std::move(coinsAdded) };
    }

private:
    mw::Header::CPtr m_pPrevHeader;
    std::vector<UTXO> m_coinsSpent;
    std::vector<Commitment> m_coinsAdded;
};

END_NAMESPACE