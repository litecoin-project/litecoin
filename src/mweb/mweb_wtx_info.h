#pragma once

#include <mw/crypto/Hasher.h>
#include <mw/models/wallet/WalletCoin.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>

namespace MWEB {

struct WalletTxInfo
{
    // When connecting a block, if an output is found that belongs to us,
    // we check if we have a CWalletTx that created it.
    // If none is found, then we assume it is a newly received coin,
    // so we create an empty transaction and store the received output's ID
    // here. The coin itself lives in the wallet's coin map (the "mweb_coin"
    // records), which is the single source of truth for coin data.
    std::optional<mw::Hash> received_output_id;

    // When connecting a block, if one of the wallet's coins is spent,
    // we check if we have a CWalletTx that spent it.
    // If none is found, then we assume it was spent by another wallet,
    // so we create an empty Transaction and store the spent hash here.
    std::optional<mw::Hash> spent_input;

    // Pre-v24 wallet records embedded the full mw::WalletCoin instead of just
    // the output ID. On deserialization of such a record the coin is parked
    // here so LoadWallet can migrate it into the wallet's coin map and
    // rewrite the record. Never serialized back out.
    std::optional<mw::WalletCoin> legacy_received_coin;

    uint256 m_hash;

    WalletTxInfo()
        : received_output_id(std::nullopt), spent_input(std::nullopt) { }

    static WalletTxInfo Received(mw::Hash output_id)
    {
        WalletTxInfo wtx_info;
        wtx_info.received_output_id = std::move(output_id);
        wtx_info.m_hash = wtx_info.CalcHash();
        return wtx_info;
    }

    static WalletTxInfo Spent(mw::Hash spent)
    {
        WalletTxInfo wtx_info;
        wtx_info.spent_input = std::move(spent);
        wtx_info.m_hash = wtx_info.CalcHash();
        return wtx_info;
    }

    bool operator==(const WalletTxInfo& rhs) const noexcept
    {
        return received_output_id == rhs.received_output_id && spent_input == rhs.spent_input;
    }

    // Serialization tag. The first byte of a pre-v24 record was a bool, so
    // 0x00 (spent) and 0x01 (received, full coin embedded) belong to the
    // legacy format. The spent layout is unchanged; received records are
    // written with the 0x02 tag and carry only the output ID.
    static constexpr uint8_t TAG_SPENT{0x00};
    static constexpr uint8_t TAG_LEGACY_RECEIVED{0x01};
    static constexpr uint8_t TAG_RECEIVED{0x02};

    SERIALIZE_METHODS(WalletTxInfo, obj)
    {
        // Only instances built via Received()/Spent() may be written; a
        // default-constructed one has neither side and no valid encoding.
        SER_WRITE(obj, assert(obj.received_output_id || obj.spent_input));
        uint8_t tag{TAG_SPENT};
        SER_WRITE(obj, tag = obj.received_output_id ? TAG_RECEIVED : TAG_SPENT);
        READWRITE(tag);

        if (tag == TAG_LEGACY_RECEIVED) {
            mw::WalletCoin coin;
            READWRITE(coin);
            SER_READ(obj, obj.received_output_id = coin.output_id);
            SER_READ(obj, obj.legacy_received_coin = std::make_optional<mw::WalletCoin>(std::move(coin)));
        } else if (tag == TAG_RECEIVED || tag == TAG_SPENT) {
            mw::Hash output_id;
            SER_WRITE(obj, output_id = tag == TAG_RECEIVED ? *obj.received_output_id : *obj.spent_input);
            READWRITE(output_id);
            if (tag == TAG_RECEIVED) {
                SER_READ(obj, obj.received_output_id = std::make_optional<mw::Hash>(std::move(output_id)));
            } else {
                SER_READ(obj, obj.spent_input = std::make_optional<mw::Hash>(std::move(output_id)));
            }
        } else {
            throw std::ios_base::failure("Unknown MWEB WalletTxInfo tag");
        }

        SER_READ(obj, obj.m_hash = obj.CalcHash());
    }

    static WalletTxInfo FromHex(const std::string& str)
    {
        CDataStream stream(MakeByteSpan(ParseHex(str)), SER_DISK, PROTOCOL_VERSION);

        WalletTxInfo wtx_info;
        stream >> wtx_info;
        return wtx_info;
    }

    std::string ToHex() const
    {
        CDataStream stream(SER_DISK, PROTOCOL_VERSION);
        stream << *this;
        return HexStr(Span<std::byte>(stream.data(), stream.size()));
    }

    const uint256& GetHash() const {
        return m_hash;
    }

private:
    uint256 CalcHash() const {
        if (!!received_output_id) {
            return uint256(Hasher().Append<int8_t>('R').Append(*received_output_id).hash().vec());
        } else {
            return uint256(Hasher().Append<int8_t>('S').Append(*spent_input).hash().vec());
        }
    }
};

} // namespace MWEB
