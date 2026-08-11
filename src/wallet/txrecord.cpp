#include <wallet/txrecord.h>
#include <wallet/receive.h>
#include <wallet/wallet.h>

#include <chain.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <util/check.h>

#include <chrono>

using namespace std::chrono;

namespace wallet {

bool WalletTxRecord::UpdateStatusIfNeeded(const uint256& block_hash)
{
    assert(!block_hash.IsNull());

    // Check if update is needed
    if (status.m_cur_block_hash == block_hash && !status.needsUpdate) {
        return false;
    }

    // Try locking the wallet
    TRY_LOCK(m_pWallet->cs_wallet, locked_wallet);
    if (!locked_wallet) {
        return false;
    }

    int64_t block_time = -1;
    CHECK_NONFATAL(m_pWallet->chain().findBlock(m_pWallet->GetLastBlockHash(), interfaces::FoundBlock().time(block_time)));

    // Sort order, unrecorded transactions sort to the top
    // Sub-components sorted with standard outputs first, MWEB outputs second, then MWEB pegouts third.
    std::string idx = strprintf("0%03d", 0);
    if (index) {
        if (index->IsOutPoint()) {
            idx = strprintf("0%03u", index->ToOutPoint().n);
        } else if (index->IsMWEBOutputID()) {
            idx = "1" + index->ToMWEBOutputID().ToHex();
        } else if (index->IsPegoutIndex()) {
            const PegoutIndex& pegout_idx = index->ToPegoutIndex();
            idx = "2" + pegout_idx.kernel_id.ToHex() + strprintf("%03d", pegout_idx.pos);
        }
    }

    const int block_height = m_wtx->state<TxStateConfirmed>() ? m_wtx->state<TxStateConfirmed>()->confirmed_block_height : std::numeric_limits<int>::max();
    const int blocks_to_maturity = m_pWallet->GetTxBlocksToMaturity(*m_wtx);

    status.sortKey = strprintf("%010d-%01d-%010u-%s",
                               block_height,
                               m_wtx->IsCoinBase() ? 1 : 0,
                               m_wtx->nTimeReceived,
                               idx);
    status.countsForBalance = CachedTxIsTrusted(*m_pWallet, *m_wtx) && !(blocks_to_maturity > 0);
    status.depth = m_pWallet->GetTxDepthInMainChain(*m_wtx);
    status.m_cur_block_hash = block_hash;

    if (m_pWallet->IsTxInMainChain(*m_wtx)) {
        status.matures_in = blocks_to_maturity;
    }

    // For generated transactions, determine maturity
    if (type == WalletTxRecord::Type::Generated || m_wtx->IsHogEx()) {
        if (blocks_to_maturity > 0) {
            status.status = TxRecordStatus::Immature;

            if (!m_pWallet->IsTxInMainChain(*m_wtx)) {
                status.status = TxRecordStatus::NotAccepted;
            }
        } else {
            status.status = TxRecordStatus::Confirmed;
        }
    } else {
        if (status.depth < 0) {
            status.status = TxRecordStatus::Conflicted;
        } else if (status.depth == 0) {
            status.status = TxRecordStatus::Unconfirmed;
            if (m_wtx->isAbandoned())
                status.status = TxRecordStatus::Abandoned;
        } else if (status.depth < RecommendedNumConfirmations) {
            status.status = TxRecordStatus::Confirming;
        } else {
            status.status = TxRecordStatus::Confirmed;
        }
    }

    status.needsUpdate = false;
    return true;
}

const uint256& WalletTxRecord::GetTxHash() const
{
    assert(m_wtx != nullptr);
    return m_wtx->GetHash();
}

std::string WalletTxRecord::GetTxString() const
{
    assert(m_wtx != nullptr);

    if (m_wtx->IsPartialMWEB()) {
        if (m_wtx->mweb_wtx_info->received_output_id) {
            const mw::Hash& output_id = *m_wtx->mweb_wtx_info->received_output_id;
            LOCK(m_pWallet->cs_wallet);
            mw::WalletCoin coin;
            if (m_pWallet->GetMWEBWalletCoin(output_id, coin)) {
                return strprintf("MWEB Output(ID=%s, amount=%d)", output_id.ToHex(), coin.amount);
            }
            return strprintf("MWEB Output(ID=%s)", output_id.ToHex());
        } else if (m_wtx->mweb_wtx_info->spent_input) {
            return strprintf("MWEB Input(ID=%s)\n", m_wtx->mweb_wtx_info->spent_input->ToHex());
        }
    }

    return m_wtx->tx->ToString();
}

int64_t WalletTxRecord::GetTxTime() const
{
    assert(m_wtx != nullptr);
    return m_wtx->GetTxTime();
}

std::string WalletTxRecord::GetType() const
{
    switch (this->type) {
        case Other: return "Other";
        case Generated: return "Generated";
        case SendToAddress: return "SendToAddress";
        case SendToOther: return "SendToOther";
        case RecvWithAddress: return "RecvWithAddress";
        case RecvFromOther: return "RecvFromOther";
        case SendToSelf: return "SendToSelf";
    }

    assert(false);
}

UniValue WalletTxRecord::ToUniValue() const
{
    UniValue entry(UniValue::VOBJ);

    entry.pushKV("type", GetType());
    entry.pushKV("amount", ValueFromAmount(GetAmount()));
    entry.pushKV("net", ValueFromAmount(GetNet()));

    CTxDestination destination = DecodeDestination(this->address);
    if (CachedTxIsFromMe(*m_pWallet, *m_wtx, ISMINE_WATCH_ONLY) || (IsValidDestination(destination) && (m_pWallet->IsMine(destination) & ISMINE_WATCH_ONLY))) {
        entry.pushKV("involvesWatchonly", true);
    }

    if (IsValidDestination(destination)) {
        const auto* address_book_entry = m_pWallet->FindAddressBookEntry(destination);
        if (address_book_entry) {
            entry.pushKV("label", address_book_entry->GetLabel());
        }
    }

    if (!this->address.empty()) {
        entry.pushKV("address", this->address);
    }

    if (this->index) {
        if (this->index->IsOutPoint()) {
            entry.pushKV("vout", (int)this->index->ToOutPoint().n);
        } else if (this->index->IsMWEBOutputID()) {
            entry.pushKV("mweb_out", this->index->ToMWEBOutputID().ToHex());
        } else if (this->index->IsPegoutIndex()) {
            const PegoutIndex& pegout_idx = this->index->ToPegoutIndex();
            entry.pushKV("pegout", pegout_idx.kernel_id.ToHex() + ":" + std::to_string(pegout_idx.pos));
        }
    }

    if (this->debit > 0) {
        entry.pushKV("fee", ValueFromAmount(-this->fee));
        entry.pushKV("abandoned", m_wtx->isAbandoned());
    }

    return entry;
}

} // namespace wallet
