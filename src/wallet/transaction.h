// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TRANSACTION_H
#define BITCOIN_WALLET_TRANSACTION_H

#include <consensus/amount.h>
#include <mweb/mweb_wtx_info.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <wallet/componentid.h>
#include <wallet/ismine.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <util/overloaded.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <list>
#include <variant>
#include <vector>

namespace wallet {
//! State of transaction confirmed in a block.
struct TxStateConfirmed {
    //! Serialized nIndex value for confirmed MWEB-only wallet rows that do not
    //! correspond to a base-chain transaction position.
    static constexpr int NO_POSITION_IN_BLOCK{-2};

    uint256 confirmed_block_hash;
    int confirmed_block_height;
    int position_in_block;

    explicit TxStateConfirmed(const uint256& block_hash, int height, int index) : confirmed_block_hash(block_hash), confirmed_block_height(height), position_in_block(index) {}

    bool HasPositionInBlock() const noexcept { return position_in_block >= 0; }
};

//! State of transaction added to mempool.
struct TxStateInMempool {
};

//! State of rejected transaction that conflicts with a confirmed block.
struct TxStateConflicted {
    uint256 conflicting_block_hash;
    int conflicting_block_height;

    explicit TxStateConflicted(const uint256& block_hash, int height) : conflicting_block_hash(block_hash), conflicting_block_height(height) {}
};

//! State of transaction not confirmed or conflicting with a known block and
//! not in the mempool. May conflict with the mempool, or with an unknown block,
//! or be abandoned, never broadcast, or rejected from the mempool for another
//! reason.
struct TxStateInactive {
    bool abandoned;

    explicit TxStateInactive(bool abandoned = false) : abandoned(abandoned) {}
};

//! State of transaction loaded in an unrecognized state with unexpected hash or
//! index values. Treated as inactive (with serialized hash and index values
//! preserved) by default, but may enter another state if transaction is added
//! to the mempool, or confirmed, or abandoned, or found conflicting.
struct TxStateUnrecognized {
    uint256 block_hash;
    int index;

    TxStateUnrecognized(const uint256& block_hash, int index) : block_hash(block_hash), index(index) {}
};

//! All possible CWalletTx states
using TxState = std::variant<TxStateConfirmed, TxStateInMempool, TxStateConflicted, TxStateInactive, TxStateUnrecognized>;

//! Subset of states transaction sync logic is implemented to handle.
using SyncTxState = std::variant<TxStateConfirmed, TxStateInMempool, TxStateInactive>;

//! Try to interpret deserialized TxStateUnrecognized data as a recognized state.
static inline TxState TxStateInterpretSerialized(TxStateUnrecognized data)
{
    if (data.block_hash == uint256::ZERO) {
        if (data.index == 0) return TxStateInactive{};
    } else if (data.block_hash == uint256::ONE) {
        if (data.index == -1) return TxStateInactive{/*abandoned=*/true};
    } else if (data.index >= 0 || data.index == TxStateConfirmed::NO_POSITION_IN_BLOCK) {
        return TxStateConfirmed{data.block_hash, /*height=*/-1, data.index};
    } else if (data.index == -1) {
        return TxStateConflicted{data.block_hash, /*height=*/-1};
    }
    return data;
}

//! Get TxState serialized block hash. Inverse of TxStateInterpretSerialized.
static inline uint256 TxStateSerializedBlockHash(const TxState& state)
{
    return std::visit(util::Overloaded{
        [](const TxStateInactive& inactive) { return inactive.abandoned ? uint256::ONE : uint256::ZERO; },
        [](const TxStateInMempool& in_mempool) { return uint256::ZERO; },
        [](const TxStateConfirmed& confirmed) { return confirmed.confirmed_block_hash; },
        [](const TxStateConflicted& conflicted) { return conflicted.conflicting_block_hash; },
        [](const TxStateUnrecognized& unrecognized) { return unrecognized.block_hash; }
    }, state);
}

//! Get TxState serialized block index. Inverse of TxStateInterpretSerialized.
static inline int TxStateSerializedIndex(const TxState& state)
{
    return std::visit(util::Overloaded{
        [](const TxStateInactive& inactive) { return inactive.abandoned ? -1 : 0; },
        [](const TxStateInMempool& in_mempool) { return 0; },
        [](const TxStateConfirmed& confirmed) { return confirmed.position_in_block; },
        [](const TxStateConflicted& conflicted) { return -1; },
        [](const TxStateUnrecognized& unrecognized) { return unrecognized.index; }
    }, state);
}


typedef std::map<std::string, std::string> mapValue_t;

enum class OutputIdMode {
    //! Return IDs for outputs physically present in CWalletTx::tx.
    TX_OUTPUTS,
    //! Return IDs visible to wallet accounting, including MWEB receive metadata
    //! stored on partial wallet rows when not already present in tx.
    WALLET_OUTPUTS,
};

/** Legacy class used for deserializing vtxPrev for backwards compatibility.
 * vtxPrev was removed in commit 93a18a3650292afbb441a47d1fa1b94aeb0164e3,
 * but old wallet.dat files may still contain vtxPrev vectors of CMerkleTxs.
 * These need to get deserialized for field alignment when deserializing
 * a CWalletTx, but the deserialized values are discarded.**/
class CMerkleTx
{
public:
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        CTransactionRef tx;
        uint256 hashBlock;
        std::vector<uint256> vMerkleBranch;
        int nIndex;

        s >> tx >> hashBlock >> vMerkleBranch >> nIndex;
    }
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx
{
public:
    /**
     * Key/value map with information about the transaction.
     *
     * The following keys can be read and written through the map and are
     * serialized in the wallet database:
     *
     *     "comment", "to"   - comment strings provided to sendtoaddress,
     *                         and sendmany wallet RPCs
     *     "replaces_txid"   - txid (as HexStr) of transaction replaced by
     *                         bumpfee on transaction created by bumpfee
     *     "replaced_by_txid" - txid (as HexStr) of transaction created by
     *                         bumpfee on transaction replaced by bumpfee
     *     "from", "message" - obsolete fields that could be set in UI prior to
     *                         2011 (removed in commit 4d9b223)
     *
     * The following keys are serialized in the wallet database, but shouldn't
     * be read or written through the map (they will be temporarily added and
     * removed from the map during serialization):
     *
     *     "fromaccount"     - serialized strFromAccount value
     *     "n"               - serialized nOrderPos value
     *     "timesmart"       - serialized nTimeSmart value
     *     "pegout_indices"  - serialized pegout_indices value
     *     "mweb_info"       - serialized mweb_wtx_info value
     *     "spent"           - serialized vfSpent value that existed prior to
     *                         2014 (removed in commit 93a18a3)
     */
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //!< time received by this node
    /**
     * Stable timestamp that never changes, and reflects the order a transaction
     * was added to the wallet. Timestamp is based on the block time for a
     * transaction added as part of a block, or else the time when the
     * transaction was received if it wasn't part of a block, with the timestamp
     * adjusted in both cases so timestamp order matches the order transactions
     * were added to the wallet. More details can be found in
     * CWallet::ComputeTimeSmart().
     */
    unsigned int nTimeSmart;
    /**
     * From me flag is set to 1 for transactions that were created by the wallet
     * on this bitcoin node, and set to 0 for transactions that were created
     * externally and came in through the network or sendrawtransaction RPC.
     */
    bool fFromMe;
    int64_t nOrderPos; //!< position in ordered transaction list
    std::multimap<int64_t, CWalletTx*>::const_iterator m_it_wtxOrdered;
    
    std::optional<MWEB::WalletTxInfo> mweb_wtx_info; // MWEB: Received mw::WalletCoin or Hash of spent MWEB coin
    std::vector<std::pair<mw::Hash, size_t>> pegout_indices; // MWEB: For HogEx transactions, output indices of pegouts belonging to this wallet

    // memory only
    enum AmountType { DEBIT, CREDIT, IMMATURE_CREDIT, AVAILABLE_CREDIT, FEE, AMOUNTTYPE_ENUM_ELEMENTS };
    mutable CachableAmount m_amounts[AMOUNTTYPE_ENUM_ELEMENTS];
    /**
     * This flag is true if all m_amounts caches are empty. This is particularly
     * useful in places where MarkDirty is conditionally called and the
     * condition can be expensive and thus can be skipped if the flag is true.
     * See MarkDestinationsDirty.
     */
    mutable bool m_is_cache_empty{true};
    mutable bool fChangeCached;
    mutable CAmount nChangeCached;

    CWalletTx(CTransactionRef tx, const TxState& state, std::optional<MWEB::WalletTxInfo> mweb_wtx_info_)
        : mweb_wtx_info(std::move(mweb_wtx_info_)), tx(std::move(tx)), m_state(state)
    {
        Init();
    }

    void Init()
    {
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        fChangeCached = false;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    CTransactionRef tx;
    TxState m_state;

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        mapValue_t mapValueCopy = mapValue;

        mapValueCopy["fromaccount"] = "";
        if (nOrderPos != -1) {
            mapValueCopy["n"] = ToString(nOrderPos);
        }
        if (nTimeSmart) {
            mapValueCopy["timesmart"] = strprintf("%u", nTimeSmart);
        }

        CWalletTx::WritePegoutIndices(pegout_indices, mapValueCopy);
        if (mweb_wtx_info.has_value()) {
            mapValueCopy["mweb_info"] = mweb_wtx_info->ToHex();
        }

        std::vector<uint8_t> dummy_vector1; //!< Used to be vMerkleBranch
        std::vector<uint8_t> dummy_vector2; //!< Used to be vtxPrev
        bool dummy_bool = false; //!< Used to be fSpent
        uint256 serializedHash = TxStateSerializedBlockHash(m_state);
        int serializedIndex = TxStateSerializedIndex(m_state);
        s << tx << serializedHash << dummy_vector1 << serializedIndex << dummy_vector2 << mapValueCopy << vOrderForm << fTimeReceivedIsTxTime << nTimeReceived << fFromMe << dummy_bool;
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        Init();

        std::vector<uint256> dummy_vector1; //!< Used to be vMerkleBranch
        std::vector<CMerkleTx> dummy_vector2; //!< Used to be vtxPrev
        bool dummy_bool; //! Used to be fSpent
        uint256 serialized_block_hash;
        int serializedIndex;
        s >> tx >> serialized_block_hash >> dummy_vector1 >> serializedIndex >> dummy_vector2 >> mapValue >> vOrderForm >> fTimeReceivedIsTxTime >> nTimeReceived >> fFromMe >> dummy_bool;

        m_state = TxStateInterpretSerialized({serialized_block_hash, serializedIndex});

        const auto it_op = mapValue.find("n");
        nOrderPos = (it_op != mapValue.end()) ? LocaleIndependentAtoi<int64_t>(it_op->second) : -1;
        const auto it_ts = mapValue.find("timesmart");
        nTimeSmart = (it_ts != mapValue.end()) ? static_cast<unsigned int>(LocaleIndependentAtoi<int64_t>(it_ts->second)) : 0;

        CWalletTx::ReadPegoutIndices(pegout_indices, mapValue);
        mweb_wtx_info = mapValue.count("mweb_info") ? std::make_optional(MWEB::WalletTxInfo::FromHex(mapValue["mweb_info"])) : std::nullopt;

        mapValue.erase("fromaccount");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
        mapValue.erase("mweb_info");
        mapValue.erase("pegout_indices");
    }

    void SetTx(CTransactionRef arg)
    {
        tx = std::move(arg);
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        m_amounts[DEBIT].Reset();
        m_amounts[CREDIT].Reset();
        m_amounts[IMMATURE_CREDIT].Reset();
        m_amounts[AVAILABLE_CREDIT].Reset();
        m_amounts[FEE].Reset();
        fChangeCached = false;
        m_is_cache_empty = true;
    }

    /** True if only scriptSigs are different */
    bool IsEquivalentTo(const CWalletTx& tx) const;

    bool InMempool() const;

    int64_t GetTxTime() const;

    template<typename T> const T* state() const { return std::get_if<T>(&m_state); }
    template<typename T> T* state() { return std::get_if<T>(&m_state); }

    bool isAbandoned() const { return state<TxStateInactive>() && state<TxStateInactive>()->abandoned; }
    bool isConflicted() const { return state<TxStateConflicted>(); }
    bool isUnconfirmed() const { return !isAbandoned() && !isConflicted() && !isConfirmed(); }
    bool isConfirmed() const { return state<TxStateConfirmed>(); }
    bool IsCoinBase() const { return tx->IsCoinBase(); }
    bool IsHogEx() const { return tx->IsHogEx(); }

    const uint256& GetHash() const
    {
        if (IsPartialMWEB()) {
            return mweb_wtx_info->GetHash();
        }

        return tx->GetHash();
    }

    const uint256& GetWitnessHash() const { return tx->GetWitnessHash(); }
    
    std::vector<AnyInput> GetInputs() const
    {
        std::vector<AnyInput> inputs = tx->GetInputs();
        if (mweb_wtx_info && mweb_wtx_info->spent_input) {
            inputs.push_back(*mweb_wtx_info->spent_input);
        }

        return inputs;
    }

    //! Return spendable output ids created by tx according to mode.
    std::vector<AnyOutputID> GetOutputIDs(const OutputIdMode mode = OutputIdMode::WALLET_OUTPUTS) const
    {
        std::vector<AnyOutputID> output_ids;
        for (const AnyOutput& output : tx->GetOutputs()) {
            output_ids.push_back(output.GetID());
        }

        if (mode == OutputIdMode::WALLET_OUTPUTS) {
            std::optional<mw::WalletCoin> mweb_coin = GetMWEBReceivedCoin();
            if (mweb_coin) {
                if (!tx->HasOutput(AnyOutputID{mweb_coin->output_id})) {
                    output_ids.push_back(mweb_coin->output_id);
                }
            }
        }

        return output_ids;
    }

    //! Return concrete outputs physically present in tx.
    std::vector<AnyOutput> GetTxOutputs() const
    {
        return tx->GetOutputs();
    }

    //! Return MWEB pegouts by kernel id and position.
    std::vector<std::pair<PegoutIndex, PegOutCoin>> GetMWEBPegouts() const
    {
        std::vector<std::pair<PegoutIndex, PegOutCoin>> pegouts;
        for (const mw::Kernel& kernel : tx->mweb_tx.GetKernels()) {
            const std::vector<PegOutCoin>& kernel_pegouts = kernel.GetPegOuts();
            for (size_t i = 0; i < kernel_pegouts.size(); ++i) {
                pegouts.emplace_back(PegoutIndex{kernel.GetKernelID(), i}, kernel_pegouts[i]);
            }
        }

        return pegouts;
    }

    bool IsPartialMWEB() const
    {
        return tx->IsNull() && mweb_wtx_info;
    }

    std::optional<mw::WalletCoin> GetMWEBReceivedCoin() const noexcept
    {
        return mweb_wtx_info ? mweb_wtx_info->received_wallet_coin : std::nullopt;
    }

    // Disable copying of CWalletTx objects to prevent bugs where instances get
    // copied in and out of the mapWallet map, and fields are updated in the
    // wrong copy.
    CWalletTx(CWalletTx const &) = delete;
    void operator=(CWalletTx const &x) = delete;

private:
    static void ReadPegoutIndices(std::vector<std::pair<mw::Hash, size_t>>& pegout_indices, const mapValue_t& mapValue);
    static void WritePegoutIndices(const std::vector<std::pair<mw::Hash, size_t>>& pegout_indices, mapValue_t& mapValue);
};

struct WalletTxOrderComparator {
    bool operator()(const CWalletTx* a, const CWalletTx* b) const
    {
        return a->nOrderPos < b->nOrderPos;
    }
};
} // namespace wallet

#endif // BITCOIN_WALLET_TRANSACTION_H
