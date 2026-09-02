// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <wallet/receive.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

#include <algorithm>

namespace wallet {

// Consensus freezes a specific MWEB output; never count it as spendable.
static bool IsFrozenMWEBOutput(const mw::Hash& output_id)
{
    const auto& frozen_outputs = Params().GetConsensus().frozen_mweb_output_ids;
    return std::find(frozen_outputs.begin(), frozen_outputs.end(), uint256(output_id.vec())) != frozen_outputs.end();
}

isminetype InputIsMine(const CWallet& wallet, const AnyInput& input)
{
    AssertLockHeld(wallet.cs_wallet);
    if (input.IsMWEB()) {
        return wallet.IsMine(AnyOutputID{input.ToMWEB()});
    }
    
    const CTxIn& txin = input.GetTxIn();
    const CWalletTx* prev = wallet.GetWalletTx(txin.prevout.hash);
    if (prev && txin.prevout.n < prev->tx->vout.size()) {
        return wallet.IsMine(prev->tx->GetOutput(txin.prevout.n));
    }
    return ISMINE_NO;
}

bool AllInputsMine(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    LOCK(wallet.cs_wallet);
    for (const AnyInput& txin : wtx.GetInputs()) {
        if (!(InputIsMine(wallet, txin) & filter)) return false;
    }

    return true;
}

CAmount OutputGetCredit(const CWallet& wallet, const CWalletTx& wtx, const AnyOutputID& output_id, const isminefilter& filter)
{
    // The lock must be taken before GetValue: resolving a MWEB output's value
    // reads the wallet's coin map, which cs_wallet guards.
    LOCK(wallet.cs_wallet);
    CAmount amount = wallet.GetValue(wtx, output_id);
    if (!MoneyRange(amount))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return ((wallet.IsMine(output_id) & filter) ? amount : 0);
}

CAmount TxGetCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    LOCK(wallet.cs_wallet);
    CAmount nCredit = 0;
    for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
        nCredit += OutputGetCredit(wallet, wtx, output_id, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    for (const PegOutCoin& pegout : wtx.tx->mweb_tx.GetPegOuts()) {
        if (wallet.IsMine(pegout.GetScriptPubKey()) & filter) {
            nCredit += pegout.GetAmount();
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }

    return nCredit;
}

bool AddressIsChange(const CWallet& wallet, const GenericAddress& address)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(address)) {
        if (address.IsMWEB()) {
            return wallet.GetMWWallet()->IsChange(address.GetMWEBAddress());
        } else {
            return ScriptIsChange(wallet, address.GetScript());
        }
    }

    return false;
}

bool ScriptIsChange(const CWallet& wallet, const CScript& script)
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;
        if (!wallet.FindAddressBookEntry(address)) {
            return true;
        }
    }
    return false;
}

bool OutputIsChange(const CWallet& wallet, const CWalletTx& wtx, const AnyOutputID& output_id)
{
    AssertLockHeld(wallet.cs_wallet);
    if (output_id.IsMWEB()) {
        mw::WalletCoin coin;
        if (wallet.GetMWEBWalletCoin(output_id.ToMWEB(), coin)) {
            return coin.IsChange();
        }

        return false;
    }

    return ScriptIsChange(wallet, wtx.tx->vout[output_id.ToOutPoint().n].scriptPubKey);
}

static CAmount OutputGetChange(const CWallet& wallet, const CWalletTx& wtx, const AnyOutputID& output_id) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    const CAmount amount = wallet.GetValue(wtx, output_id);
    if (!MoneyRange(amount))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (OutputIsChange(wallet, wtx, output_id) ? amount : 0);
}

CAmount TxGetChange(const CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    CAmount nChange = 0;
    for (const AnyOutputID& output_id : wtx.GetOutputIDs()) {
        nChange += OutputGetChange(wallet, wtx, output_id);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }

    for (const PegOutCoin& pegout : wtx.tx->mweb_tx.GetPegOuts()) {
        if (ScriptIsChange(wallet, pegout.GetScriptPubKey())) {
            nChange += pegout.GetAmount();
            if (!MoneyRange(nChange))
                throw std::runtime_error(std::string(__func__) + ": value out of range");
        
        }
    }

    return nChange;
}

static CAmount GetCachableAmount(const CWallet& wallet, const CWalletTx& wtx, CWalletTx::AmountType type, const isminefilter& filter)
{
    auto& amount = wtx.m_amounts[type];
    if (!amount.m_cached[filter]) {
        amount.Set(filter, type == CWalletTx::DEBIT ? wallet.GetDebit(*wtx.tx, wtx.mweb_wtx_info, filter) : TxGetCredit(wallet, wtx, filter));
        wtx.m_is_cache_empty = false;
    }
    return amount.m_value[filter];
}

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmature(wtx))
        return 0;

    CAmount credit = 0;
    const isminefilter get_amount_filter{filter & ISMINE_ALL};
    if (get_amount_filter) {
        // GetBalance can assume transactions in mapWallet won't change
        credit += GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, get_amount_filter);
    }
    return credit;
}

CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    if (wtx.GetInputs().empty())
        return 0;

    CAmount debit = 0;
    const isminefilter get_amount_filter{filter & ISMINE_ALL};
    if (get_amount_filter) {
        debit += GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, get_amount_filter);
    }
    return debit;
}

CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx)
{
    if (wtx.fChangeCached)
        return wtx.nChangeCached;
    wtx.nChangeCached = TxGetChange(wallet, wtx);
    wtx.fChangeCached = true;
    return wtx.nChangeCached;
}

CAmount CachedTxGetImmatureCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    if (wallet.IsTxImmature(wtx) && wallet.IsTxInMainChain(wtx)) {
        return GetCachableAmount(wallet, wtx, CWalletTx::IMMATURE_CREDIT, filter);
    }

    return 0;
}

CAmount CachedTxGetAvailableCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    // Avoid caching ismine for NO or ALL cases (could remove this check and simplify in the future).
    bool allow_cache = (filter & ISMINE_ALL) && (filter & ISMINE_ALL) != ISMINE_ALL;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmature(wtx))
        return 0;

    if (allow_cache && wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_cached[filter]) {
        return wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_value[filter];
    }

    bool allow_used_addresses = (filter & ISMINE_USED) || !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    CAmount nCredit = 0;
    for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
        if (output_id.IsMWEB() && IsFrozenMWEBOutput(output_id.ToMWEB())) {
            continue;
        }

        if (!wallet.IsSpent(output_id) && (allow_used_addresses || !wallet.IsSpentKey(wtx, output_id))) {
            nCredit += OutputGetCredit(wallet, wtx, output_id, filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + " : value out of range");
        }
    }

    if (allow_cache) {
        wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].Set(filter, nCredit);
        wtx.m_is_cache_empty = false;
    }

    return nCredit;
}

CAmount CachedTxGetFee(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    LOCK(wallet.cs_wallet);

    // An ID-only MWEB spend tells us which coin left the wallet, but not its
    // recipients or fee. Treat the value as an unattributed debit instead of
    // reporting the whole coin as a transaction fee.
    if (wtx.IsPartialMWEB()) {
        return 0;
    }

    if (wtx.m_amounts[CWalletTx::FEE].m_cached[filter]) {
        return wtx.m_amounts[CWalletTx::FEE].m_value[filter];
    }

    CAmount nFee = 0;

    CAmount nDebit = CachedTxGetDebit(wallet, wtx, filter);
    // debit>0 means we signed/sent this transaction
    if (nDebit > 0) {
        CAmount nValueOut = 0;
        for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
            if (!output_id.IsMWEB() && IsPegInOutput(wtx.tx->vout[output_id.ToOutPoint().n])) {
                continue;
            }

            nValueOut += wallet.GetValue(wtx, output_id);
        }

        for (const PegOutCoin& pegout : wtx.tx->mweb_tx.GetPegOuts()) {
            nValueOut += pegout.GetAmount();
        }

        nFee = nDebit - nValueOut;
    }

    // Avoid caching ismine for NO or ALL cases (could remove this check and simplify in the future).
    bool allow_cache = (filter & ISMINE_ALL) && (filter & ISMINE_ALL) != ISMINE_ALL;
    if (allow_cache) {
        wtx.m_amounts[CWalletTx::FEE].Set(filter, nFee);
        wtx.m_is_cache_empty = false;
    }

    return nFee;
}

void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                  std::list<COutputEntry>& listReceived,
                  std::list<COutputEntry>& listSent, CAmount& nFee, const isminefilter& filter,
                  bool include_change)
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    // Compute fee:
    CAmount nDebit = CachedTxGetDebit(wallet, wtx, filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        nFee = CachedTxGetFee(wallet, wtx, filter);
    }

    LOCK(wallet.cs_wallet);
    // Sent/received.
    for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS))
    {
        // The canonical peg-in output only bridges value into the MWEB
        // transaction. When the matching MWEB transaction is available, its
        // recipients describe the actual payment and the bridge output must
        // not be reported as another sent amount.
        if (!output_id.IsMWEB()) {
            mw::Hash kernel_id;
            if (wtx.tx->vout[output_id.ToOutPoint().n].scriptPubKey.IsMWEBPegin(&kernel_id) &&
                wtx.tx->HasMWEBTx() && wtx.tx->mweb_tx.GetKernelIDs().count(kernel_id) > 0) {
                continue;
            }
        }

        isminetype fIsMine = wallet.IsMine(output_id);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            if (!include_change && OutputIsChange(wallet, wtx, output_id))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!wallet.ExtractOutputDestination(wtx, output_id, address) && (output_id.IsMWEB() || !wtx.tx->vout[output_id.ToOutPoint().n].scriptPubKey.IsUnspendable()))
        {
            wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                    wtx.GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output_entry = {address, wallet.GetValue(wtx, output_id), output_id};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output_entry);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output_entry);
    }

    for (const auto& [pegout_index, pegout] : wtx.GetMWEBPegouts()) {
        const CScript& pegout_script = pegout.GetScriptPubKey();
        isminetype fIsMine = wallet.IsMine(pegout_script);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0) {
            // Don't report 'change' txouts
            if (!include_change && ScriptIsChange(wallet, pegout_script))
                continue;
        } else if (!(fIsMine & filter))
            continue;

        CTxDestination address;
        ExtractDestination(pegout_script, address);

        COutputEntry output = {address, pegout.GetAmount(), pegout_index};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }
}

bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    return (CachedTxGetDebit(wallet, wtx, filter) > 0);
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<uint256>& trusted_parents)
{
    AssertLockHeld(wallet.cs_wallet);
    int nDepth = wallet.GetTxDepthInMainChain(wtx);
    if (nDepth >= 1) return true;
    if (nDepth < 0) return false;

    // MWEB: If the HogEx is not in the main chain, then we should assume it has been replaced during a reorg.
    if (wtx.IsHogEx()) return false;

    // using wtx's cached debit
    if (!wallet.m_spend_zero_conf_change || !CachedTxIsFromMe(wallet, wtx, ISMINE_ALL)) return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!wtx.InMempool()) return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const AnyInput& input : wtx.GetInputs())
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = wallet.FindPrevTx(input);
        if (parent == nullptr) return false;
        // If we've already trusted this parent, continue
        if (trusted_parents.count(parent->GetHash())) continue;
        // Check that this specific input being spent is trusted
        if (wallet.IsMine(input.GetID()) != ISMINE_SPENDABLE) return false;
        // Recurse to check that the parent is also trusted
        if (!CachedTxIsTrusted(wallet, *parent, trusted_parents)) return false;
        trusted_parents.insert(parent->GetHash());
    }
    return true;
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx)
{
    std::set<uint256> trusted_parents;
    LOCK(wallet.cs_wallet);
    return CachedTxIsTrusted(wallet, wtx, trusted_parents);
}

Balance GetBalance(const CWallet& wallet, const int min_depth, bool avoid_reuse)
{
    Balance ret;
    isminefilter reuse_filter = avoid_reuse ? ISMINE_NO : ISMINE_USED;
    {
        LOCK(wallet.cs_wallet);
        std::set<uint256> trusted_parents;
        for (const auto& entry : wallet.mapWallet)
        {
            const CWalletTx& wtx = entry.second;
            const bool is_trusted{CachedTxIsTrusted(wallet, wtx, trusted_parents)};
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};
            const CAmount tx_credit_mine{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_SPENDABLE | reuse_filter)};
            const CAmount tx_credit_watchonly{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_WATCH_ONLY | reuse_filter)};
            if (is_trusted && tx_depth >= min_depth) {
                ret.m_mine_trusted += tx_credit_mine;
                ret.m_watchonly_trusted += tx_credit_watchonly;
            }
            if (!is_trusted && tx_depth == 0 && wtx.InMempool()) {
                ret.m_mine_untrusted_pending += tx_credit_mine;
                ret.m_watchonly_untrusted_pending += tx_credit_watchonly;
            }
            ret.m_mine_immature += CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE);
            ret.m_watchonly_immature += CachedTxGetImmatureCredit(wallet, wtx, ISMINE_WATCH_ONLY);
        }
    }
    return ret;
}

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet)
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(wallet.cs_wallet);
        std::set<uint256> trusted_parents;
        for (const auto& walletEntry : wallet.mapWallet)
        {
            const CWalletTx& wtx = walletEntry.second;

            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents))
                continue;

            if (wallet.IsTxImmature(wtx))
                continue;

            int nDepth = wallet.GetTxDepthInMainChain(wtx);
            if (nDepth < (CachedTxIsFromMe(wallet, wtx, ISMINE_ALL) ? 0 : 1))
                continue;

            for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
                CTxDestination addr;
                if (!wallet.IsMine(output_id))
                    continue;
                if (!wallet.ExtractOutputDestination(wtx, output_id, addr))
                    continue;

                CAmount n = wallet.IsSpent(output_id) ? 0 : wallet.GetValue(wtx, output_id);
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > GetAddressGroupings(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : wallet.mapWallet)
    {
        const CWalletTx& wtx = walletEntry.second;

        std::vector<AnyInput> inputs = wtx.GetInputs();
        if (inputs.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (const AnyInput& input : inputs)
            {
                CTxDestination address;
                if (!InputIsMine(wallet, input)) /* If this input isn't mine, ignore it */
                    continue;
                const CWalletTx* prev = wallet.FindPrevTx(input);
                if (!prev)
                    continue;
                if (!wallet.ExtractOutputDestination(*prev, input.GetID(), address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
                for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
                    if (OutputIsChange(wallet, wtx, output_id)) {
                        CTxDestination address;
                        if (!wallet.ExtractOutputDestination(wtx, output_id, address))
                            continue;
                        grouping.insert(address);
                    }
                }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const AnyOutputID& output_id : wtx.GetOutputIDs(OutputIdMode::WALLET_OUTPUTS)) {
            if (wallet.IsMine(output_id)) {
                CTxDestination address;
                if (!wallet.ExtractOutputDestination(wtx, output_id, address))
                   continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
        }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (const std::set<CTxDestination>& _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}
} // namespace wallet
