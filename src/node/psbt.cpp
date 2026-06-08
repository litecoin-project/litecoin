// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/tx_verify.h>
#include <mw/consensus/Weight.h>
#include <node/psbt.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <tinyformat.h>

#include <numeric>

namespace node {
namespace {
bool MWEBInputComplete(const PSBTInput& input)
{
    if (!input.mweb_sig || !input.mweb_features || !input.mweb_output_commit || !input.mweb_output_pubkey) {
        return false;
    }

    const uint8_t features = *input.mweb_features;
    if (features & mw::Input::STEALTH_KEY_FEATURE_BIT && !input.mweb_input_pubkey) {
        return false;
    }
    if (features & mw::Input::EXTRA_DATA_FEATURE_BIT && input.mweb_extra_data.empty()) {
        return false;
    }

    return true;
}

bool MWEBOutputComplete(const PSBTOutput& output)
{
    if (!output.mweb_commit || !output.mweb_features || !output.mweb_sender_pubkey || !output.mweb_output_pubkey || !output.mweb_rangeproof || !output.mweb_sig) {
        return false;
    }

    const uint8_t features = *output.mweb_features;
    if (features & mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT && !output.mweb_standard_fields) {
        return false;
    }
    if (features & mw::OutputMessage::EXTRA_DATA_FEATURE_BIT && output.mweb_extra_data.empty()) {
        return false;
    }

    return true;
}

bool MWEBKernelComplete(const PSBTKernel& kernel)
{
    if (!kernel.commit || !kernel.features || !kernel.sig) {
        return false;
    }

    const uint8_t features = *kernel.features;
    if (features & mw::Kernel::FEE_FEATURE_BIT && !kernel.fee) {
        return false;
    }
    if (features & mw::Kernel::PEGIN_FEATURE_BIT && !kernel.pegin_amount) {
        return false;
    }
    if (features & mw::Kernel::PEGOUT_FEATURE_BIT && kernel.pegouts.empty()) {
        return false;
    }
    if (features & mw::Kernel::HEIGHT_LOCK_FEATURE_BIT && !kernel.lock_height) {
        return false;
    }
    if (features & mw::Kernel::STEALTH_EXCESS_FEATURE_BIT && !kernel.stealth_commit) {
        return false;
    }
    if (features & mw::Kernel::EXTRA_DATA_FEATURE_BIT && kernel.extra_data.empty()) {
        return false;
    }

    return true;
}

std::optional<PSBTRole> GetMWEBNextRole(const PartiallySignedTransaction& psbtx)
{
    if (!psbtx.ContainsMWEBComponents()) {
        return std::nullopt;
    }

    bool has_mweb_tx_component{false};
    bool has_mweb_kernel{false};
    for (const PSBTInput& input : psbtx.inputs) {
        if (!input.IsMWEB()) {
            continue;
        }
        has_mweb_tx_component = true;
        if (!MWEBInputComplete(input)) {
            return PSBTRole::SIGNER;
        }
    }

    for (const PSBTOutput& output : psbtx.outputs) {
        if (!output.IsMWEB()) {
            continue;
        }
        has_mweb_tx_component = true;
        if (!MWEBOutputComplete(output)) {
            return PSBTRole::SIGNER;
        }
    }

    for (const PSBTKernel& kernel : psbtx.kernels) {
        has_mweb_tx_component = true;
        has_mweb_kernel = true;
        if (!MWEBKernelComplete(kernel)) {
            return PSBTRole::SIGNER;
        }
    }

    if (!has_mweb_tx_component || !has_mweb_kernel || !psbtx.mweb_tx_offset || !psbtx.mweb_stealth_offset) {
        return PSBTRole::SIGNER;
    }

    return PSBTRole::EXTRACTOR;
}

size_t EstimateMWEBWeight(const PartiallySignedTransaction& psbtx)
{
    bool has_mweb_tx_component{false};
    size_t weight{0};

    for (const PSBTInput& input : psbtx.inputs) {
        if (!input.IsMWEB()) {
            continue;
        }
        has_mweb_tx_component = true;
        weight += Weight::CalcInputWeight(input.mweb_extra_data);
    }

    for (const PSBTOutput& output : psbtx.outputs) {
        if (!output.IsMWEB()) {
            continue;
        }
        has_mweb_tx_component = true;
        const bool standard_fields = !output.mweb_features.has_value() ||
            (*output.mweb_features & mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT);
        weight += Weight::CalcOutputWeight(standard_fields, output.mweb_extra_data);
    }

    if (!psbtx.kernels.empty()) {
        has_mweb_tx_component = true;
        for (const PSBTKernel& kernel : psbtx.kernels) {
            weight += Weight::CalcKernelWeight(
                /*has_stealth_excess=*/true,
                kernel.pegouts,
                kernel.extra_data);
        }
    } else if (has_mweb_tx_component) {
        weight += Weight::CalcKernelWeight(/*has_stealth_excess=*/true, std::vector<PegOutCoin>{});
    }

    return weight;
}
} // namespace

PSBTAnalysis AnalyzePSBT(PartiallySignedTransaction psbtx)
{
    // Go through each input and build status
    PSBTAnalysis result;

    bool calc_fee = true;

    CAmount in_amt = 0;

    result.inputs.resize(psbtx.inputs.size());

    const std::optional<PSBTRole> mweb_role = GetMWEBNextRole(psbtx);

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs[i];
        PSBTInputAnalysis& input_analysis = result.inputs[i];

        // We currently only support signing all MWEB transactions at once, so MWEB inputs share the MWEB component role.
        if (input.IsMWEB()) {
            assert(mweb_role.has_value());
            if (!input.mweb_amount.has_value() || !MoneyRange(*input.mweb_amount) || !MoneyRange(in_amt + (*input.mweb_amount))) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u has invalid value", i));
                return result;
            }
            in_amt += *input.mweb_amount;
            input_analysis.has_utxo = false;
            input_analysis.is_final = (*mweb_role == PSBTRole::EXTRACTOR);
            input_analysis.next = *mweb_role;
            continue;
        }

        // We set next role here and ratchet backwards as required
        input_analysis.next = PSBTRole::EXTRACTOR;

        // Check for a UTXO
        CTxOut utxo;
        if (input.GetUTXO(utxo)) {
            if (!MoneyRange(utxo.nValue) || !MoneyRange(in_amt + utxo.nValue)) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u has invalid value", i));
                return result;
            }
            in_amt += utxo.nValue;
            input_analysis.has_utxo = true;
        } else {
            if (input.non_witness_utxo && input.prev_out >= input.non_witness_utxo->vout.size()) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u specifies invalid prevout", i));
                return result;
            }
            input_analysis.has_utxo = false;
            input_analysis.is_final = false;
            input_analysis.next = PSBTRole::UPDATER;
            calc_fee = false;
        }

        if (!utxo.IsNull() && utxo.scriptPubKey.IsUnspendable()) {
            result.SetInvalid(strprintf("PSBT is not valid. Input %u spends unspendable output", i));
            return result;
        }

        // Check if it is final
        if (!PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
            input_analysis.is_final = false;

            // Figure out what is missing
            SignatureData outdata;
            bool complete = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, 1, &outdata);

            // Things are missing
            if (!complete) {
                input_analysis.missing_pubkeys = outdata.missing_pubkeys;
                input_analysis.missing_redeem_script = outdata.missing_redeem_script;
                input_analysis.missing_witness_script = outdata.missing_witness_script;
                input_analysis.missing_sigs = outdata.missing_sigs;

                // If we are only missing signatures and nothing else, then next is signer
                if (outdata.missing_pubkeys.empty() && outdata.missing_redeem_script.IsNull() && outdata.missing_witness_script.IsNull() && !outdata.missing_sigs.empty()) {
                    input_analysis.next = PSBTRole::SIGNER;
                } else {
                    input_analysis.next = PSBTRole::UPDATER;
                }
            } else {
                input_analysis.next = PSBTRole::FINALIZER;
            }
        } else if (!utxo.IsNull()){
            input_analysis.is_final = true;
        }
    }

    // Calculate next role for PSBT by grabbing "minimum" PSBTInput next role
    result.next = PSBTRole::EXTRACTOR;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInputAnalysis& input_analysis = result.inputs[i];
        result.next = std::min(result.next, input_analysis.next);
    }
    if (mweb_role.has_value()) {
        result.next = std::min(result.next, *mweb_role);
    }
    assert(result.next > PSBTRole::CREATOR);

    if (calc_fee) {
        // Get the output amount
        CAmount out_amt = std::accumulate(psbtx.outputs.begin(), psbtx.outputs.end(), CAmount(0),
            [](CAmount a, const PSBTOutput& b) {
                if (!MoneyRange(a) || !MoneyRange(*b.amount) || !MoneyRange(a + *b.amount)) {
                    return CAmount(-1);
                }
                return a += *b.amount;
            }
        );

        if (!MoneyRange(out_amt)) {
            result.SetInvalid("PSBT is not valid. Output amount invalid");
            return result;
        }

        // Include pegin amounts.
        CAmount pegin_amt = std::accumulate(psbtx.kernels.begin(), psbtx.kernels.end(), CAmount(0),
            [](CAmount a, const PSBTKernel& b) {
                if (!MoneyRange(a)) {
                    return CAmount(-1);
                }
                if (b.pegin_amount.has_value()) {
                    if (!MoneyRange(*b.pegin_amount) || !MoneyRange(a + *b.pegin_amount)) {
                        return CAmount(-1);
                    }
                    a += *b.pegin_amount;
                }
                return a;
            }
        );

        if (!MoneyRange(pegin_amt) || !MoneyRange(in_amt + pegin_amt)) {
            result.SetInvalid("PSBT is not valid. Pegin amount invalid");
            return result;
        }

        // Include pegout amounts
        CAmount pegout_amt = std::accumulate(psbtx.kernels.begin(), psbtx.kernels.end(), CAmount(0),
            [](CAmount a, const PSBTKernel& b) {
                for (const PegOutCoin& pegout : b.pegouts) {
                    if (!MoneyRange(a) || !MoneyRange(pegout.GetAmount()) || !MoneyRange(a + pegout.GetAmount())) {
                        return CAmount(-1);
                    }
                    a += pegout.GetAmount();
                }
                return a;
            }
        );

        if (!MoneyRange(pegout_amt) || !MoneyRange(out_amt + pegout_amt)) {
            result.SetInvalid("PSBT is not valid. Pegout amount invalid");
            return result;
        }

        // Get the fee
        CAmount fee = (in_amt + pegin_amt) - (out_amt + pegout_amt);
        result.fee = fee;

        // Estimate the size
        CMutableTransaction mtx(psbtx.GetUnsignedTx());
        CCoinsView view_dummy;
        CCoinsViewCache view(&view_dummy);
        bool success = true;

        unsigned int ltc_input_idx = 0;
        for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
            PSBTInput& input = psbtx.inputs[i];
            Coin newcoin;

            if (!input.IsMWEB()) {
                if (!SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, nullptr, 1) || !input.GetUTXO(newcoin.out)) {
                    success = false;
                    break;
                }

                mtx.vin[ltc_input_idx].scriptSig = input.final_script_sig;
                mtx.vin[ltc_input_idx].scriptWitness = input.final_script_witness;
                newcoin.nHeight = 1;
                view.AddCoin(input.GetOutPoint(), std::move(newcoin), true);
                ++ltc_input_idx;
            }
        }

        if (success) {
            CTransaction ctx = CTransaction(mtx);
            size_t size(GetVirtualTransactionSize(ctx, GetTransactionSigOpCost(ctx, view, STANDARD_SCRIPT_VERIFY_FLAGS), ::nBytesPerSigOp));
            const size_t mweb_weight = EstimateMWEBWeight(psbtx);
            result.estimated_vsize = size;
            result.estimated_mweb_weight = mweb_weight;
            // Estimate fee rate
            CFeeRate feerate(fee, size, mweb_weight);
            result.estimated_feerate = feerate;
        }

    }

    return result;
}
} // namespace node
