#pragma once

// Copyright (c) 2018-2020 David Burkett
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <mw/common/Macros.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>

#include <cstdint>
#include <memory>

MW_NAMESPACE

class HeaderAndPegs final : public Traits::ISerializable
{
public:
    using CPtr = std::shared_ptr<const HeaderAndPegs>;

    //
    // Constructors
    //
    HeaderAndPegs(
        const mw::Header::CPtr& pHeader,
        std::vector<PegInCoin>&& pegins,
        std::vector<PegOutCoin>&& pegouts
    )
        : m_pHeader(pHeader),
        m_pegins(std::move(pegins)),
        m_pegouts(std::move(pegouts)) { }

    //
    // Getters
    //
    const mw::Header::CPtr& GetHeader() const noexcept { return m_pHeader; }
    const std::vector<PegInCoin>& GetPegins() const noexcept { return m_pegins; }
    const std::vector<PegOutCoin>& GetPegouts() const noexcept { return m_pegouts; }

    //
    // Serialization/Deserialization
    //
    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer
            .Append(m_pHeader)
            .AppendVec(m_pegins)
            .AppendVec(m_pegouts);
    }

    static HeaderAndPegs Deserialize(Deserializer& deserializer)
    {
        mw::Header header = mw::Header::Deserialize(deserializer);

        std::vector<PegInCoin> pegins;
        const uint64_t num_pegins = deserializer.Read<uint64_t>();
        for (uint64_t i = 0; i < num_pegins; i++)
        {
            pegins.push_back(PegInCoin::Deserialize(deserializer));
        }

        std::vector<PegOutCoin> pegouts;
        const uint64_t num_pegouts = deserializer.Read<uint64_t>();
        for (uint64_t i = 0; i < num_pegouts; i++)
        {
            pegouts.push_back(PegOutCoin::Deserialize(deserializer));
        }

        return HeaderAndPegs{
            std::make_shared<const mw::Header>(std::move(header)),
            std::move(pegins),
            std::move(pegouts)
        };
    }

private:
    mw::Header::CPtr m_pHeader;
    std::vector<PegInCoin> m_pegins;
    std::vector<PegOutCoin> m_pegouts;
};

END_NAMESPACE