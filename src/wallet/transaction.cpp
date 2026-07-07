// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/transaction.h>

namespace wallet {
bool CWalletTx::IsEquivalentTo(const CWalletTx& _tx) const
{
        CMutableTransaction tx1 {*this->tx};
        CMutableTransaction tx2 {*_tx.tx};
        for (auto& txin : tx1.vin) txin.scriptSig = CScript();
        for (auto& txin : tx2.vin) txin.scriptSig = CScript();
        return CTransaction(tx1) == CTransaction(tx2) && this->mweb_wtx_info == _tx.mweb_wtx_info;
}

bool CWalletTx::InMempool() const
{
    return state<TxStateInMempool>();
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

void CWalletTx::ReadPegoutIndices(std::vector<std::pair<mw::Hash, size_t>>& pegout_indices, const mapValue_t& mapValue)
{
    if (!mapValue.count("pegout_indices")) {
        return;
    }

    std::vector<uint8_t> bytes = ParseHex(mapValue.at("pegout_indices"));
    CDataStream s(MakeByteSpan(std::move(bytes)), SER_DISK, PROTOCOL_VERSION);

    size_t num_indices = ReadVarInt<CDataStream, VarIntMode::DEFAULT, size_t>(s);
    for (size_t i = 0; i < num_indices; i++) {
        mw::Hash kernel_id;
        s >> kernel_id;
        size_t sub_idx = ReadVarInt<CDataStream, VarIntMode::DEFAULT, size_t>(s);

        pegout_indices.push_back({std::move(kernel_id), sub_idx});
    }
}

void CWalletTx::WritePegoutIndices(const std::vector<std::pair<mw::Hash, size_t>>& pegout_indices, mapValue_t& mapValue)
{
    if (pegout_indices.empty()) {
        return;
    }

    CDataStream s(SER_DISK, PROTOCOL_VERSION);
    WriteVarInt<CDataStream, VarIntMode::DEFAULT, size_t>(s, pegout_indices.size());
    for (const auto& pegout_idx : pegout_indices) {
        pegout_idx.first.Serialize(s);
        WriteVarInt<CDataStream, VarIntMode::DEFAULT, size_t>(s, pegout_idx.second);
    }

    mapValue["pegout_indices"] = HexStr(Span<std::byte>(s.data(), s.size()));
}
} // namespace wallet
