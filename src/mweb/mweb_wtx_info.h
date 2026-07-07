#pragma once

#include <mw/crypto/Hasher.h>
#include <mw/models/wallet/WalletCoin.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstdint>
#include <optional>
#include <string>

namespace MWEB {

struct WalletTxInfo
{
    // When connecting a block, if an output is found that belongs to us,
    // we check if we have a CWalletTx that created it.
    // If none is found, then we assume it is a newly received coin,
    // so we create an empty transaction and store the received coin here.
    std::optional<mw::WalletCoin> received_wallet_coin;

    // When connecting a block, if one of the wallet's coins is spent,
    // we check if we have a CWalletTx that spent it.
    // If none is found, then we assume it was spent by another wallet,
    // so we create an empty Transaction and store the spent hash here.
    std::optional<mw::Hash> spent_input;

    uint256 m_hash;

    WalletTxInfo()
        : received_wallet_coin(std::nullopt), spent_input(std::nullopt) { }
    WalletTxInfo(mw::WalletCoin received)
        : received_wallet_coin(std::move(received)), spent_input(std::nullopt), m_hash(CalcHash()) {}
    WalletTxInfo(mw::Hash spent)
        : received_wallet_coin(std::nullopt), spent_input(std::move(spent)), m_hash(CalcHash()) {}

    bool operator==(const WalletTxInfo& rhs) const noexcept
    {
        return received_wallet_coin == rhs.received_wallet_coin && spent_input == rhs.spent_input;
    }

    SERIALIZE_METHODS(WalletTxInfo, obj)
    {
        bool received = !!obj.received_wallet_coin;
        READWRITE(received);

        if (received) {
            mw::WalletCoin coin;
            SER_WRITE(obj, coin = *obj.received_wallet_coin);
            READWRITE(coin);
            SER_READ(obj, obj.received_wallet_coin = std::make_optional<mw::WalletCoin>(std::move(coin)));
        } else {
            mw::Hash output_id;
            SER_WRITE(obj, output_id = *obj.spent_input);
            READWRITE(output_id);
            SER_READ(obj, obj.spent_input = std::make_optional<mw::Hash>(std::move(output_id)));
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
        if (!!received_wallet_coin) {
            return uint256(Hasher().Append<int8_t>('R').Append(received_wallet_coin->output_id).hash().vec());
        } else {
            return uint256(Hasher().Append<int8_t>('S').Append(*spent_input).hash().vec());
        }
    }
};

} // namespace MWEB
