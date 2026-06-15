// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_COINCONTROL_H
#define BITCOIN_WALLET_COINCONTROL_H

#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <script/keyorigin.h>
#include <script/signingprovider.h>
#include <script/standard.h>

#include <optional>
#include <algorithm>
#include <map>
#include <set>

namespace wallet {
const int DEFAULT_MIN_DEPTH = 0;
const int DEFAULT_MAX_DEPTH = 9999999;

//! Default for -avoidpartialspends
static constexpr bool DEFAULT_AVOIDPARTIALSPENDS = false;

/** Coin Control Features. */
class CCoinControl
{
public:
    //! Custom change destination, if not set an address is generated
    CTxDestination destChange = CNoDestination();
    //! Override the default change type if set, ignored if destChange is set
    std::optional<OutputType> m_change_type;
    //! If false, only safe inputs will be used
    bool m_include_unsafe_inputs = false;
    //! If true, the selection process can add extra unselected inputs from the wallet
    //! while requires all selected inputs be used
    bool m_allow_other_inputs = false;
    //! Includes watch only addresses which are solvable
    bool fAllowWatchOnly = false;
    //! Override automatic min/max checks on fee, m_feerate must be set if true
    bool fOverrideFeeRate = false;
    //! Override the wallet's m_pay_tx_fee if set
    std::optional<CFeeRate> m_feerate;
    //! Override the default confirmation target if set
    std::optional<unsigned int> m_confirm_target;
    //! Override the wallet's m_signal_rbf if set
    std::optional<bool> m_signal_bip125_rbf;
    //! Avoid partial use of funds sent to a given address
    bool m_avoid_partial_spends = DEFAULT_AVOIDPARTIALSPENDS;
    //! Forbids inclusion of dirty (previously used) addresses
    bool m_avoid_address_reuse = false;
    //! Fee estimation mode to control arguments to estimateSmartFee
    FeeEstimateMode m_fee_mode = FeeEstimateMode::UNSET;
    //! Minimum chain depth value for coin availability
    int m_min_depth = DEFAULT_MIN_DEPTH;
    //! Maximum chain depth value for coin availability
    int m_max_depth = DEFAULT_MAX_DEPTH;
    //! SigningProvider that has pubkeys and scripts to do spend size estimation for external inputs
    FlatSigningProvider m_external_provider;
	//! Peg-in from LTC address to own MWEB address
	bool fPegIn = false;
	//! Peg-out from MWEB address to own LTC address
	bool fPegOut = false;

    CCoinControl();

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool IsSelected(const AnyOutputID& output_id) const
    {
        return (setSelected.count(output_id) > 0);
    }

    bool IsExternalSelected(const AnyOutputID& output_id) const
    {
        return (m_external_outputs.count(output_id) > 0);
    }

    bool GetExternalOutput(const AnyOutputID& output_id, AnyOutput& output) const
    {
        const auto ext_it = m_external_outputs.find(output_id);
        if (ext_it == m_external_outputs.end()) {
            return false;
        }
        output = ext_it->second;
        return true;
    }

    void Select(const AnyOutputID& output_id)
    {
        setSelected.insert(output_id);
    }

    void SelectExternal(const AnyOutputID& output_id, const AnyOutput& output)
    {
        setSelected.insert(output_id);
        m_external_outputs.emplace(output_id, output);
    }

    void UnSelect(const AnyOutputID& output_id)
    {
        setSelected.erase(output_id);
    }

    void UnSelectAll()
    {
        setSelected.clear();
    }

    void ListSelected(std::vector<AnyOutputID>& vOutpoints) const
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

    void SetInputWeight(const AnyOutputID& output_id, int64_t weight)
    {
        m_input_weights[output_id] = weight;
    }

    bool HasInputWeight(const AnyOutputID& output_id) const
    {
        return m_input_weights.count(output_id) > 0;
    }

    int64_t GetInputWeight(const AnyOutputID& output_id) const
    {
        auto it = m_input_weights.find(output_id);
        assert(it != m_input_weights.end());
        return it->second;
    }

private:
    std::set<AnyOutputID> setSelected;
    std::map<AnyOutputID, AnyOutput> m_external_outputs;
    //! Map from AnyOutputID to the maximum weight for that input
    std::map<AnyOutputID, int64_t> m_input_weights;
};
} // namespace wallet

#endif // BITCOIN_WALLET_COINCONTROL_H
