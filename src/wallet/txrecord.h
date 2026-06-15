#pragma once

#include <consensus/amount.h>
#include <wallet/componentid.h>
#include <univalue.h>
#include <optional>
#include <variant>

namespace wallet {

// Forward Declarations
class CWallet;
class CWalletTx;

struct TxRecordStatus {
    enum Status {
        Confirmed, /**< Have 6 or more confirmations (normal tx) or fully mature (mined tx) **/
        /// Normal (sent/received) transactions
        Unconfirmed,    /**< Not yet mined into a block **/
        Confirming,     /**< Confirmed, but waiting for the recommended number of confirmations **/
        Conflicted,     /**< Conflicts with other transaction or mempool **/
        Abandoned,      /**< Abandoned from the wallet **/
        /// Generated (mined) transactions
        Immature,   /**< Mined but waiting for maturity */
        NotAccepted /**< Mined but not accepted */
    };

    /// Transaction counts towards available balance
    bool countsForBalance;
    /// Sorting key based on status
    std::string sortKey;

    /** @name Generated (mined) transactions
       @{*/
    int matures_in;
    /**@}*/

    /** @name Reported status
       @{*/
    Status status;
    int64_t depth;
    int64_t open_for; /**< Timestamp if status==OpenUntilDate, otherwise number
                      of additional blocks that need to be mined before
                      finalization */
    /**@}*/

    /** Current block hash (to know whether cached status is still valid) */
    uint256 m_cur_block_hash{};

    bool needsUpdate;
};

class WalletTxRecord
{
public:
    WalletTxRecord(const CWallet* pWallet, const CWalletTx* wtx, const AnyOutputID& output_id)
        : m_pWallet(pWallet), m_wtx(wtx), index(std::make_optional(output_id.IsMWEB() ? GenericComponentID(output_id.ToMWEB()) : GenericComponentID(output_id.ToOutPoint()))) {}
    WalletTxRecord(const CWallet* pWallet, const CWalletTx* wtx, const PegoutIndex& pegout_index)
        : m_pWallet(pWallet), m_wtx(wtx), index(std::make_optional(GenericComponentID(pegout_index))) {}
    WalletTxRecord(const CWallet* pWallet, const CWalletTx* wtx)
        : m_pWallet(pWallet), m_wtx(wtx), index(std::nullopt) {}

    static const int RecommendedNumConfirmations = 6;

    enum Type {
        Other,
        Generated,
        SendToAddress,
        SendToOther,
        RecvWithAddress,
        RecvFromOther,
        SendToSelf,
    };

    Type type{Type::Other};
    std::string address{};
    CAmount debit{0};
    CAmount credit{0};
    CAmount fee{0};
    bool involvesWatchAddress{false};

    // Cached status attributes
    TxRecordStatus status;

    // Updates the transaction record's cached status attributes.
    bool UpdateStatusIfNeeded(const uint256& block_hash);

    const CWalletTx& GetWTX() const noexcept { return *m_wtx; }
    const uint256& GetTxHash() const;
    std::string GetTxString() const;
    int64_t GetTxTime() const;
    CAmount GetAmount() const noexcept
    {
        // Self-sends should report the net (fee) amount.
        if (type == SendToSelf) {
            return GetNet();
        }
        return credit > 0 ? credit : debit;
    }
    CAmount GetDisplayAmount() const noexcept { return credit + debit; }
    CAmount GetNet() const noexcept { return credit + debit + fee; }

    UniValue ToUniValue() const;

    // Returns the formatted component index.
    std::string GetComponentIndex() const { return index.has_value() ? index->ToString() : ""; }

private:
    // Pointer to the CWallet instance
    const CWallet* m_pWallet;

    // The actual CWalletTx
    const CWalletTx* m_wtx;

    // The index of the transaction component this record is for.
    std::optional<GenericComponentID> index;

    std::string GetType() const;
};

} // namespace wallet
