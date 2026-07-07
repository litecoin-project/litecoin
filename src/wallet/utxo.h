#pragma once

#include <consensus/amount.h>
#include <mw/models/wallet/WalletCoin.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/address.h>
#include <script/standard.h>

#include <optional>

namespace wallet {

/** A UTXO under consideration for use in funding a new transaction. */
struct CWalletUTXO
{
private:
    /** The output's value minus fees required to spend it.*/
    std::optional<CAmount> effective_value;

    /** The fee required to spend this output at the transaction's target feerate. */
    std::optional<CAmount> fee;

public:
    /** The outpoint identifying this UTXO */
    COutPoint outpoint;

    /** The output itself */
    CTxOut txout;

    /**
     * Depth in block chain.
     * If > 0: the tx is on chain and has this many confirmations.
     * If = 0: the tx is waiting confirmation.
     * If < 0: a conflicting tx is on chain and has this many confirmations. */
    int depth;

    /** Pre-computed estimated size of this output as a fully-signed input in a transaction. Can be -1 if it could not be calculated */
    int input_bytes;

    /** Whether we have the private keys to spend this output */
    bool spendable;

    /** Whether we know how to spend this output, ignoring the lack of keys */
    bool solvable;

    /**
     * Whether this output is considered safe to spend. Unconfirmed transactions
     * from outside keys and unconfirmed replacement transactions are considered
     * unsafe and will not be used to fund new spending transactions.
     */
    bool safe;

    /** The time of the transaction containing this output as determined by CWalletTx::nTimeSmart */
    int64_t time;

    /** Whether the transaction containing this output is sent from the owning wallet */
    bool from_me;

    /** The fee required to spend this output at the consolidation feerate. */
    CAmount long_term_fee{0};

    CWalletUTXO(const COutPoint& outpoint, const CTxOut& txout, int depth, int input_bytes, bool spendable, bool solvable, bool safe, int64_t time, bool from_me, const std::optional<CFeeRate> feerate = std::nullopt)
        : outpoint{outpoint},
          txout{txout},
          depth{depth},
          input_bytes{input_bytes},
          spendable{spendable},
          solvable{solvable},
          safe{safe},
          time{time},
          from_me{from_me}
    {
        if (feerate) {
            fee = input_bytes < 0 ? 0 : feerate.value().GetFee(input_bytes, 0);
            effective_value = txout.nValue - fee.value();
        }
    }

    CWalletUTXO(const COutPoint& outpoint, const CTxOut& txout, int depth, int input_bytes, bool spendable, bool solvable, bool safe, int64_t time, bool from_me, const CAmount fees)
        : CWalletUTXO(outpoint, txout, depth, input_bytes, spendable, solvable, safe, time, from_me)
    {
        // if input_bytes is unknown, then fees should be 0, if input_bytes is known, then the fees should be a positive integer or 0 (input_bytes known and fees = 0 only happens in the tests)
        assert((input_bytes < 0 && fees == 0) || (input_bytes > 0 && fees >= 0));
        fee = fees;
        effective_value = txout.nValue - fee.value();
    }

    std::string ToString() const;

    bool operator<(const CWalletUTXO& rhs) const
    {
        return outpoint < rhs.outpoint;
    }

    CAmount GetFee() const
    {
        assert(fee.has_value());
        return fee.value();
    }

    CAmount GetEffectiveValue() const
    {
        assert(effective_value.has_value());
        return effective_value.value();
    }
};

struct MwebWalletUTXO
{
    mw::WalletCoin coin;
    int depth;
    StealthAddress address;
    bool spendable;
    bool solvable;
    bool from_me;
    uint256 wtx_hash;

    bool operator<(const MwebWalletUTXO& rhs) const
    {
        return coin.output_id < rhs.coin.output_id;
    }
};

struct AnyWalletUTXO
{
    AnyWalletUTXO(const CWalletUTXO& out) : m_output(out) {}
    AnyWalletUTXO(const MwebWalletUTXO& out) : m_output(out) {}

    bool operator<(const AnyWalletUTXO& rhs) const
    {
        return m_output < rhs.m_output;
    }

    bool IsMWEB() const noexcept { return std::holds_alternative<MwebWalletUTXO>(m_output); }

    CWalletUTXO& GetLTC() noexcept
    {
        assert(!IsMWEB());
        return std::get<CWalletUTXO>(m_output);
    }

    const MwebWalletUTXO& GetMWEB() const noexcept
    {
        assert(IsMWEB());
        return std::get<MwebWalletUTXO>(m_output);
    }

    bool IsSpendable() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).spendable;
        return std::get<CWalletUTXO>(m_output).spendable;
    }

    bool IsSolvable() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).solvable;
        return std::get<CWalletUTXO>(m_output).solvable;
    }

    bool IsSafe() const
    {
        if (IsMWEB()) return true;
        return std::get<CWalletUTXO>(m_output).safe;
    }

    bool GetDestination(CTxDestination& dest) const
    {
        if (IsMWEB()) {
            dest = std::get<MwebWalletUTXO>(m_output).address;
            return true;
        } else {
            const CWalletUTXO& out = std::get<CWalletUTXO>(m_output);
            return ExtractDestination(out.txout.scriptPubKey, dest);
        }
    }

    GenericAddress GetAddress() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).address;

        const CWalletUTXO& out = std::get<CWalletUTXO>(m_output);
        return out.txout.scriptPubKey;
    }

    CAmount GetValue() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).coin.amount;

        const CWalletUTXO& out = std::get<CWalletUTXO>(m_output);
        return out.txout.nValue;
    }

    CAmount GetFee() const
    {
        if (IsMWEB()) return 0;
        return std::get<CWalletUTXO>(m_output).GetFee();
    }

    CAmount GetLongTermFee() const
    {
        if (IsMWEB()) return 0;
        return std::get<CWalletUTXO>(m_output).long_term_fee;
    }

    CAmount GetEffectiveValue() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).coin.amount;
        return std::get<CWalletUTXO>(m_output).GetEffectiveValue();
    }

    int GetInputBytes() const
    {
        if (IsMWEB()) return 0;
        return std::get<CWalletUTXO>(m_output).input_bytes;
    }

    int GetDepth() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).depth;
        return std::get<CWalletUTXO>(m_output).depth;
    }

    bool IsFromMe() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).from_me;
        return std::get<CWalletUTXO>(m_output).from_me;
    }

    const uint256& GetTxHash() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).wtx_hash;
        return std::get<CWalletUTXO>(m_output).outpoint.hash;
    }

    AnyOutputID GetID() const
    {
        if (IsMWEB()) return std::get<MwebWalletUTXO>(m_output).coin.output_id;

        const CWalletUTXO& out = std::get<CWalletUTXO>(m_output);
        return out.outpoint;
    }

    std::variant<CWalletUTXO, MwebWalletUTXO> m_output;
};

}
