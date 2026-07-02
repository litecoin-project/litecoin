// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <consensus/amount.h>
#include <hash.h>
#include <script/script.h>
#include <serialize.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <version.h>

#include <cassert>
#include <stdexcept>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), mweb_tx(tx.mweb_tx.ToMutable()), m_hogEx(tx.m_hogEx) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB);
}

uint256 CTransaction::ComputeHash() const
{
    if (IsMWEBOnly()) {
        return uint256(mweb_tx.m_transaction->GetHash().vec());
    }

    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness() || IsMWEBOnly()) {
        return hash;
    }

    return SerializeHash(*this, SER_GETHASH, SERIALIZE_NO_MWEB);
}

CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), mweb_tx(tx.mweb_tx), m_hogEx(tx.m_hogEx), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), mweb_tx(tx.mweb_tx), m_hogEx(tx.m_hogEx), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";

    if (!mweb_tx.IsNull()) {
        str += "    " + mweb_tx.ToString() + "\n";
    }

    return str;
}

std::vector<AnyInput> CTransaction::GetInputs() const noexcept
{
    std::vector<AnyInput> inputs;

    for (const CTxIn& txin : vin) {
        inputs.push_back(txin);
    }

    for (const mw::Hash& spent_id : mweb_tx.GetSpentIDs()) {
        inputs.push_back(spent_id);
    }

    return inputs;
}

bool CTransaction::HasOutput(const AnyOutputID& output_id) const noexcept
{
    if (output_id.IsMWEB()) {
        return mweb_tx.GetOutputIDs().count(output_id.ToMWEB()) > 0;
    } else {
        return vout.size() > output_id.ToOutPoint().n;
    }
}

AnyOutput CTransaction::GetOutput(const size_t index) const noexcept
{
    assert(vout.size() > index);
    return AnyOutput{COutPoint(GetHash(), index), vout[index]};
}

AnyOutput CTransaction::GetOutput(const AnyOutputID& output_id) const noexcept
{
    if (output_id.IsMWEB()) {
        mw::Output output;
        bool has_output = mweb_tx.GetOutput(output_id.ToMWEB(), output);
        assert(has_output);
        return AnyOutput{output};
    } else {
        const COutPoint& outpoint = output_id.ToOutPoint();
        assert(vout.size() > outpoint.n);
        return AnyOutput{outpoint, vout[outpoint.n]};
    }
}

std::vector<AnyOutput> CTransaction::GetOutputs() const noexcept
{
    std::vector<AnyOutput> outputs;

    for (size_t n = 0; n < vout.size(); n++) {
        outputs.push_back(AnyOutput{COutPoint(GetHash(), n), vout[n]});
    }

    for (const mw::Output& output : mweb_tx.GetOutputs()) {
        outputs.push_back(AnyOutput{output});
    }

    return outputs;
}

std::vector<AnyInput> CMutableTransaction::GetInputs() const noexcept
{
    std::vector<AnyInput> inputs;

    for (const CTxIn& txin : vin) {
        inputs.push_back(txin);
    }

    for (const mw::MutableInput& mweb_input : mweb_tx.inputs) {
        inputs.push_back(mweb_input.output_id);
    }

    return inputs;
}
