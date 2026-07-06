#pragma once

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/tx/Output.h>
#include <mw/mmr/LeafIndex.h>
#include <serialize.h>

MW_NAMESPACE

class Coin : public Traits::ISerializable
{
    static constexpr int32_t MEMPOOL_BLOCK_HEIGHT{std::numeric_limits<int32_t>::max()};
    static constexpr uint64_t MEMPOOL_LEAF_IDX{std::numeric_limits<uint64_t>::max() / 2};

public:
    using CPtr = std::shared_ptr<const Coin>;

    Coin() : m_blockHeight(0), m_leafIdx(), m_output() { }
    Coin(const int32_t blockHeight, mmr::LeafIndex leafIdx, mw::Output output)
        : m_blockHeight(blockHeight), m_leafIdx(std::move(leafIdx)), m_output(std::move(output)) { }

    static Coin ForMempool(mw::Output output) noexcept { return Coin(MEMPOOL_BLOCK_HEIGHT, mmr::LeafIndex::At(MEMPOOL_LEAF_IDX), std::move(output)); }

    bool IsInMempool() const noexcept { return m_blockHeight == MEMPOOL_BLOCK_HEIGHT && m_leafIdx.Get() == MEMPOOL_LEAF_IDX; }
    int32_t GetBlockHeight() const noexcept { return m_blockHeight; }
    const mmr::LeafIndex& GetLeafIndex() const noexcept { return m_leafIdx; }
    const mw::Output& GetOutput() const noexcept { return m_output; }

    const mw::Hash& GetOutputID() const noexcept { return m_output.GetOutputID(); }
    const Commitment& GetCommitment() const noexcept { return m_output.GetCommitment(); }
    const PublicKey& GetSenderPubKey() const noexcept { return m_output.GetSenderPubKey(); }
    const PublicKey& GetReceiverPubKey() const noexcept { return m_output.GetReceiverPubKey(); }
    const OutputMessage& GetOutputMessage() const noexcept { return m_output.GetOutputMessage(); }
    const RangeProof::CPtr& GetRangeProof() const noexcept { return m_output.GetRangeProof(); }
    const Signature& GetSignature() const noexcept { return m_output.GetSignature(); }
    ProofData BuildProofData() const noexcept { return m_output.BuildProofData(); }

    IMPL_SERIALIZABLE(Coin, obj)
    {
        READWRITE(obj.m_blockHeight, obj.m_leafIdx, obj.m_output);
    }

private:
    int32_t m_blockHeight;
    mmr::LeafIndex m_leafIdx;
    mw::Output m_output;
};

/// <summary>
/// MWEB coin wrapper that supports serialization into multiple formats.
/// </summary>
class NetCoin
{
public:
    static const uint8_t FULL_COIN = 0x00;
    static const uint8_t HASH_ONLY = 0x01;
    static const uint8_t COMPACT_COIN = 0x02;

    NetCoin() = default;
    NetCoin(const uint8_t format, const Coin::CPtr& coin)
        : m_format(format), m_coin(coin) { }

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        s << COMPACTSIZE(m_coin->GetLeafIndex().Get());

        if (m_format == FULL_COIN) {
            s << m_coin->GetOutput();
        } else if (m_format == HASH_ONLY) {
            s << m_coin->GetOutputID();
        } else if (m_format == COMPACT_COIN) {
            s << m_coin->GetCommitment();
            s << m_coin->GetSenderPubKey();
            s << m_coin->GetReceiverPubKey();
            s << m_coin->GetOutputMessage();
            s << m_coin->GetRangeProof()->GetHash();
            s << m_coin->GetSignature();
        } else {
            throw std::ios_base::failure("Unsupported MWEB coin serialization format");
        }
    }

private:
    uint8_t m_format;
    Coin::CPtr m_coin;
};

END_NAMESPACE
