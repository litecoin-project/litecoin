// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <mw/models/tx/Kernel.h>

namespace {
template <typename T>
bool MergeOptionalStrict(std::optional<T>& dst, const std::optional<T>& src)
{
    if (!src.has_value()) {
        return true;
    }
    if (!dst.has_value()) {
        dst = src;
        return true;
    }
    return *dst == *src;
}

bool EqualOutputStandardFields(const mw::OutputStandardFields& a, const mw::OutputStandardFields& b)
{
    return a.key_exchange_pubkey == b.key_exchange_pubkey &&
           a.view_tag == b.view_tag &&
           a.masked_value == b.masked_value &&
           a.masked_nonce == b.masked_nonce;
}

bool MergeOutputStandardFields(std::optional<mw::OutputStandardFields>& dst, const std::optional<mw::OutputStandardFields>& src)
{
    if (!src.has_value()) {
        return true;
    }
    if (!dst.has_value()) {
        dst = src;
        return true;
    }
    return EqualOutputStandardFields(*dst, *src);
}

bool MergeRangeProof(std::optional<RangeProof::CPtr>& dst, const std::optional<RangeProof::CPtr>& src)
{
    if (!src.has_value()) {
        return true;
    }
    if (!dst.has_value()) {
        dst = src;
        return true;
    }
    if (!*dst || !*src) {
        return *dst == *src;
    }
    return **dst == **src;
}

template <typename T>
bool MergeVectorStrict(std::vector<T>& dst, const std::vector<T>& src)
{
    if (src.empty()) {
        return true;
    }
    if (dst.empty()) {
        dst = src;
        return true;
    }
    return dst == src;
}

bool HasMWEBSignatureOrProof(const PartiallySignedTransaction& psbt)
{
    for (const PSBTInput& input : psbt.inputs) {
        if (input.mweb_sig.has_value()) {
            return true;
        }
    }
    for (const PSBTOutput& output : psbt.outputs) {
        if (output.mweb_rangeproof.has_value() || output.mweb_sig.has_value()) {
            return true;
        }
    }
    for (const PSBTKernel& kernel : psbt.kernels) {
        if (kernel.sig.has_value()) {
            return true;
        }
    }
    return false;
}

void ClearTxModifiable(PartiallySignedTransaction& psbt)
{
    if (psbt.m_tx_modifiable.has_value()) {
        psbt.m_tx_modifiable->reset();
    }
}

bool MergeUnknownStrict(std::map<std::vector<unsigned char>, std::vector<unsigned char>>& dst, const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& src)
{
    for (const auto& [key, value] : src) {
        auto [it, inserted] = dst.emplace(key, value);
        if (!inserted && it->second != value) {
            return false;
        }
    }
    return true;
}

bool MergeProprietaryStrict(std::set<PSBTProprietary>& dst, const std::set<PSBTProprietary>& src)
{
    for (const PSBTProprietary& prop : src) {
        auto [it, inserted] = dst.insert(prop);
        if (!inserted &&
            (it->identifier != prop.identifier ||
             it->subtype != prop.subtype ||
             it->value != prop.value)) {
            return false;
        }
    }
    return true;
}

bool IsMWEBPeginScript(const CScript& script, mw::Hash* kernel_id = nullptr)
{
    mw::Hash id;
    if (!script.IsMWEBPegin(&id)) {
        return false;
    }
    if (kernel_id != nullptr) {
        *kernel_id = std::move(id);
    }
    return true;
}

bool IsMWEBPeginPlaceholderScript(const CScript& script)
{
    mw::Hash kernel_id;
    return IsMWEBPeginScript(script, &kernel_id) && kernel_id.IsZero();
}

bool IsFinalMWEBPeginScript(const CScript& script)
{
    mw::Hash kernel_id;
    return IsMWEBPeginScript(script, &kernel_id) && !kernel_id.IsZero();
}

bool HasBaseSignatureData(const PartiallySignedTransaction& psbt)
{
    for (const PSBTInput& input : psbt.inputs) {
        if (input.IsMWEB()) {
            continue;
        }
        if (!input.partial_sigs.empty() ||
            !input.final_script_sig.empty() ||
            !input.final_script_witness.IsNull() ||
            !input.m_tap_key_sig.empty() ||
            !input.m_tap_script_sigs.empty()) {
            return true;
        }
    }
    return false;
}

bool MergeScriptStrict(
    std::optional<CScript>& dst,
    const std::optional<CScript>& src,
    const bool dst_has_base_sigs,
    const bool src_has_base_sigs)
{
    if (!src.has_value()) {
        return true;
    }
    if (!dst.has_value()) {
        dst = src;
        return true;
    }
    if (*dst == *src) {
        return true;
    }

    if (IsMWEBPeginPlaceholderScript(*dst) && IsFinalMWEBPeginScript(*src)) {
        if (dst_has_base_sigs) {
            return false;
        }
        dst = src;
        return true;
    }

    if (IsFinalMWEBPeginScript(*dst) && IsMWEBPeginPlaceholderScript(*src)) {
        return !src_has_base_sigs;
    }

    return false;
}

std::optional<mw::Hash> GetKernelID(const PSBTKernel& kernel)
{
    if (!kernel.features.has_value() || !kernel.commit.has_value() || !kernel.sig.has_value()) {
        return std::nullopt;
    }

    return mw::Kernel(
        *kernel.features,
        kernel.fee,
        kernel.pegin_amount,
        kernel.pegouts,
        kernel.lock_height,
        kernel.stealth_commit,
        kernel.extra_data,
        *kernel.commit,
        *kernel.sig).GetKernelID();
}

uint8_t CalculateKernelFeatures(const PSBTKernel& kernel)
{
    uint8_t features{0};
    features |= kernel.fee.has_value() ? mw::Kernel::FEE_FEATURE_BIT : 0;
    features |= kernel.pegin_amount.has_value() ? mw::Kernel::PEGIN_FEATURE_BIT : 0;
    features |= !kernel.pegouts.empty() ? mw::Kernel::PEGOUT_FEATURE_BIT : 0;
    features |= kernel.lock_height.has_value() ? mw::Kernel::HEIGHT_LOCK_FEATURE_BIT : 0;
    features |= kernel.stealth_commit.has_value() ? mw::Kernel::STEALTH_EXCESS_FEATURE_BIT : 0;
    features |= !kernel.extra_data.empty() ? mw::Kernel::EXTRA_DATA_FEATURE_BIT : 0;
    return features;
}

bool KernelFeaturesConsistent(const PSBTKernel& kernel)
{
    return !kernel.features.has_value() || *kernel.features == CalculateKernelFeatures(kernel);
}

bool MergePSBTInput(PSBTInput& dst, const PSBTInput& src, const bool strict_metadata)
{
    if (dst.IsMWEB() != src.IsMWEB()) {
        return false;
    }

    if (!dst.IsMWEB()) {
        if (dst.prev_txid != src.prev_txid || dst.prev_out != src.prev_out) {
            return false;
        }
        if (strict_metadata &&
            (!MergeUnknownStrict(dst.unknown, src.unknown) ||
             !MergeProprietaryStrict(dst.m_proprietary, src.m_proprietary))) {
            return false;
        }
        dst.Merge(src);
        return true;
    }

    if (dst.mweb_output_id != src.mweb_output_id) {
        return false;
    }

    if (!MergeOptionalStrict(dst.mweb_output_commit, src.mweb_output_commit) ||
        !MergeOptionalStrict(dst.mweb_output_pubkey, src.mweb_output_pubkey) ||
        !MergeOptionalStrict(dst.mweb_input_pubkey, src.mweb_input_pubkey) ||
        !MergeOptionalStrict(dst.mweb_features, src.mweb_features) ||
        !MergeOptionalStrict(dst.mweb_sig, src.mweb_sig) ||
        !MergeOptionalStrict(dst.mweb_amount, src.mweb_amount) ||
        !MergeOptionalStrict(dst.mweb_shared_secret, src.mweb_shared_secret) ||
        !MergeOptionalStrict(dst.mweb_key_exchange_pubkey, src.mweb_key_exchange_pubkey) ||
        !MergeOptionalStrict(dst.mweb_address_descriptor, src.mweb_address_descriptor) ||
        !MergeVectorStrict(dst.mweb_extra_data, src.mweb_extra_data) ||
        !MergeUnknownStrict(dst.unknown, src.unknown)) {
        return false;
    }

    return MergeProprietaryStrict(dst.m_proprietary, src.m_proprietary);
}

bool MergePSBTOutput(PSBTOutput& dst, const PSBTOutput& src, const bool dst_has_base_sigs, const bool src_has_base_sigs, const bool strict_metadata)
{
    if (dst.IsMWEB() != src.IsMWEB()) {
        return false;
    }

    if (!MergeOptionalStrict(dst.amount, src.amount) ||
        !MergeScriptStrict(dst.script, src.script, dst_has_base_sigs, src_has_base_sigs)) {
        return false;
    }

    dst.hd_keypaths.insert(src.hd_keypaths.begin(), src.hd_keypaths.end());
    dst.m_tap_bip32_paths.insert(src.m_tap_bip32_paths.begin(), src.m_tap_bip32_paths.end());

    if (dst.redeem_script.empty() && !src.redeem_script.empty()) dst.redeem_script = src.redeem_script;
    if (dst.witness_script.empty() && !src.witness_script.empty()) dst.witness_script = src.witness_script;
    if (dst.m_tap_internal_key.IsNull() && !src.m_tap_internal_key.IsNull()) dst.m_tap_internal_key = src.m_tap_internal_key;
    if (dst.m_tap_tree.empty() && !src.m_tap_tree.empty()) dst.m_tap_tree = src.m_tap_tree;

    if (!dst.IsMWEB()) {
        if (strict_metadata) {
            return MergeUnknownStrict(dst.unknown, src.unknown) &&
                   MergeProprietaryStrict(dst.m_proprietary, src.m_proprietary);
        }

        dst.unknown.insert(src.unknown.begin(), src.unknown.end());
        dst.m_proprietary.insert(src.m_proprietary.begin(), src.m_proprietary.end());
        return true;
    }

    return MergeUnknownStrict(dst.unknown, src.unknown) &&
           MergeProprietaryStrict(dst.m_proprietary, src.m_proprietary) &&
           MergeOptionalStrict(dst.mweb_stealth_address, src.mweb_stealth_address) &&
           MergeOptionalStrict(dst.mweb_commit, src.mweb_commit) &&
           MergeOptionalStrict(dst.mweb_features, src.mweb_features) &&
           MergeOptionalStrict(dst.mweb_sender_pubkey, src.mweb_sender_pubkey) &&
           MergeOptionalStrict(dst.mweb_output_pubkey, src.mweb_output_pubkey) &&
           MergeOutputStandardFields(dst.mweb_standard_fields, src.mweb_standard_fields) &&
           MergeRangeProof(dst.mweb_rangeproof, src.mweb_rangeproof) &&
           MergeOptionalStrict(dst.mweb_sig, src.mweb_sig) &&
           MergeVectorStrict(dst.mweb_extra_data, src.mweb_extra_data);
}

bool MergePSBTKernel(PSBTKernel& dst, const PSBTKernel& src)
{
    if (!KernelFeaturesConsistent(dst) || !KernelFeaturesConsistent(src)) {
        return false;
    }

    if (!MergeOptionalStrict(dst.commit, src.commit) ||
        !MergeOptionalStrict(dst.stealth_commit, src.stealth_commit) ||
        !MergeOptionalStrict(dst.fee, src.fee) ||
        !MergeOptionalStrict(dst.pegin_amount, src.pegin_amount) ||
        !MergeVectorStrict(dst.pegouts, src.pegouts) ||
        !MergeOptionalStrict(dst.lock_height, src.lock_height) ||
        !MergeVectorStrict(dst.extra_data, src.extra_data) ||
        !MergeOptionalStrict(dst.sig, src.sig) ||
        !MergeUnknownStrict(dst.unknown, src.unknown)) {
        return false;
    }

    if (dst.features.has_value() || src.features.has_value()) {
        dst.features = CalculateKernelFeatures(dst);
    }

    return true;
}

bool MWEBMergeCompatible(const PartiallySignedTransaction& dst, const PartiallySignedTransaction& src)
{
    if (dst.inputs.size() != src.inputs.size() ||
        dst.outputs.size() != src.outputs.size() ||
        dst.kernels.size() != src.kernels.size()) {
        return false;
    }

    uint32_t dst_locktime;
    uint32_t src_locktime;
    if (!dst.ComputeTimeLock(dst_locktime) || !src.ComputeTimeLock(src_locktime) || dst_locktime != src_locktime) {
        return false;
    }

    return true;
}
} // namespace

bool VerifyPeginOutputs(const PartiallySignedTransaction& psbt, const bool require_final)
{
    std::vector<const PSBTKernel*> pegin_kernels;
    for (const PSBTKernel& kernel : psbt.kernels) {
        if (kernel.pegin_amount.has_value()) {
            pegin_kernels.push_back(&kernel);
        }
    }

    struct PeginOutput
    {
        const PSBTOutput* output;
        mw::Hash kernel_id;
    };

    std::vector<PeginOutput> pegin_outputs;
    bool has_final_pegin_script{false};
    for (const PSBTOutput& output : psbt.outputs) {
        if (!output.script.has_value()) {
            continue;
        }

        mw::Hash kernel_id;
        if (!IsMWEBPeginScript(*output.script, &kernel_id)) {
            continue;
        }

        if (!kernel_id.IsZero()) {
            has_final_pegin_script = true;
        }
        pegin_outputs.push_back(PeginOutput{&output, std::move(kernel_id)});
    }

    // Validate every association that can already be formed, even if a
    // partial packet is still missing outputs or kernel maps at the end.
    for (size_t i = 0; i < pegin_outputs.size() && i < pegin_kernels.size(); ++i) {
        const PeginOutput& pegin_output = pegin_outputs[i];
        const PSBTKernel& pegin_kernel = *pegin_kernels[i];

        if (!pegin_output.output->amount.has_value()) {
            if (require_final) {
                return false;
            }
        } else if (*pegin_output.output->amount != *pegin_kernel.pegin_amount) {
            return false;
        }

        if (pegin_output.kernel_id.IsZero()) {
            if (require_final) {
                return false;
            }
            continue;
        }

        const std::optional<mw::Hash> kernel_id = GetKernelID(pegin_kernel);
        if (!kernel_id.has_value() || pegin_output.kernel_id != *kernel_id) {
            return false;
        }
    }

    if (pegin_outputs.size() != pegin_kernels.size()) {
        // Partial packets may be observed while placeholder outputs and peg-in
        // kernel fields are still being added. Once any script is finalized,
        // or before extraction, the positional association must be complete.
        if (require_final || has_final_pegin_script) {
            return false;
        }
    }

    return true;
}

void PSBTInput::Merge(const PSBTInput& input)
{
    assert(prev_txid == input.prev_txid);
    assert(*prev_out == *input.prev_out);

    if (!non_witness_utxo && input.non_witness_utxo) non_witness_utxo = input.non_witness_utxo;
    if (witness_utxo.IsNull() && !input.witness_utxo.IsNull()) {
        witness_utxo = input.witness_utxo;
    }

    partial_sigs.insert(input.partial_sigs.begin(), input.partial_sigs.end());
    ripemd160_preimages.insert(input.ripemd160_preimages.begin(), input.ripemd160_preimages.end());
    sha256_preimages.insert(input.sha256_preimages.begin(), input.sha256_preimages.end());
    hash160_preimages.insert(input.hash160_preimages.begin(), input.hash160_preimages.end());
    hash256_preimages.insert(input.hash256_preimages.begin(), input.hash256_preimages.end());
    hd_keypaths.insert(input.hd_keypaths.begin(), input.hd_keypaths.end());
    unknown.insert(input.unknown.begin(), input.unknown.end());
    m_tap_script_sigs.insert(input.m_tap_script_sigs.begin(), input.m_tap_script_sigs.end());
    m_tap_scripts.insert(input.m_tap_scripts.begin(), input.m_tap_scripts.end());
    m_tap_bip32_paths.insert(input.m_tap_bip32_paths.begin(), input.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !input.redeem_script.empty()) redeem_script = input.redeem_script;
    if (witness_script.empty() && !input.witness_script.empty()) witness_script = input.witness_script;
    if (final_script_sig.empty() && !input.final_script_sig.empty()) final_script_sig = input.final_script_sig;
    if (final_script_witness.IsNull() && !input.final_script_witness.IsNull()) final_script_witness = input.final_script_witness;
    if (m_tap_key_sig.empty() && !input.m_tap_key_sig.empty()) m_tap_key_sig = input.m_tap_key_sig;
    if (m_tap_internal_key.IsNull() && !input.m_tap_internal_key.IsNull()) m_tap_internal_key = input.m_tap_internal_key;
    if (m_tap_merkle_root.IsNull() && !input.m_tap_merkle_root.IsNull()) m_tap_merkle_root = input.m_tap_merkle_root;
    if (sequence == std::nullopt && input.sequence != std::nullopt) sequence = input.sequence;
    if (time_locktime == std::nullopt && input.time_locktime != std::nullopt) time_locktime = input.time_locktime;
    if (height_locktime == std::nullopt && input.height_locktime != std::nullopt) height_locktime = input.height_locktime;
}

void PSBTOutput::Merge(const PSBTOutput& output)
{
    assert(*amount == *output.amount);
    assert(*script == *output.script);

    hd_keypaths.insert(output.hd_keypaths.begin(), output.hd_keypaths.end());
    unknown.insert(output.unknown.begin(), output.unknown.end());
    m_tap_bip32_paths.insert(output.m_tap_bip32_paths.begin(), output.m_tap_bip32_paths.end());

    if (redeem_script.empty() && !output.redeem_script.empty()) redeem_script = output.redeem_script;
    if (witness_script.empty() && !output.witness_script.empty()) witness_script = output.witness_script;
    if (m_tap_internal_key.IsNull() && !output.m_tap_internal_key.IsNull()) m_tap_internal_key = output.m_tap_internal_key;
    if (m_tap_tree.empty() && !output.m_tap_tree.empty()) m_tap_tree = output.m_tap_tree;
}

bool PartiallySignedTransaction::Merge(const PartiallySignedTransaction& psbt)
{
    const bool contains_mweb = ContainsMWEBComponents() || psbt.ContainsMWEBComponents();

    // Prohibited to merge two PSBTs over different transactions.
    // For MWEB PSBTs, compare structure explicitly because the base txid does
    // not cover MWEB data and MWEB signing can finalize peg-in scriptPubKeys.
    if (!contains_mweb && GetUniqueID() != psbt.GetUniqueID()) {
        return false;
    }

    if (tx_version != psbt.tx_version) {
        return false;
    }

    if (inputs.size() != psbt.inputs.size() ||
        outputs.size() != psbt.outputs.size() ||
        kernels.size() != psbt.kernels.size()) {
        return false;
    }

    if (contains_mweb && !MWEBMergeCompatible(*this, psbt)) {
        return false;
    }

    PartiallySignedTransaction merged_psbt{*this};
    const bool dst_has_base_sigs = HasBaseSignatureData(merged_psbt);
    const bool src_has_base_sigs = HasBaseSignatureData(psbt);

    for (unsigned int i = 0; i < merged_psbt.inputs.size(); ++i) {
        if (!MergePSBTInput(merged_psbt.inputs[i], psbt.inputs[i], /*strict_metadata=*/contains_mweb)) {
            return false;
        }
    }
    for (unsigned int i = 0; i < merged_psbt.outputs.size(); ++i) {
        if (!MergePSBTOutput(merged_psbt.outputs[i], psbt.outputs[i], dst_has_base_sigs, src_has_base_sigs, /*strict_metadata=*/contains_mweb)) {
            return false;
        }
    }
    for (unsigned int i = 0; i < merged_psbt.kernels.size(); ++i) {
        if (!MergePSBTKernel(merged_psbt.kernels[i], psbt.kernels[i])) {
            return false;
        }
    }
    if (!MergeOptionalStrict(merged_psbt.mweb_tx_offset, psbt.mweb_tx_offset) ||
        !MergeOptionalStrict(merged_psbt.mweb_stealth_offset, psbt.mweb_stealth_offset) ||
        !VerifyPeginOutputs(merged_psbt, /*require_final=*/false)) {
        return false;
    }
    for (auto& xpub_pair : psbt.m_xpubs) {
        if (merged_psbt.m_xpubs.count(xpub_pair.first) == 0) {
            merged_psbt.m_xpubs[xpub_pair.first] = xpub_pair.second;
        } else {
            merged_psbt.m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
        }
    }
    if (merged_psbt.fallback_locktime == std::nullopt && psbt.fallback_locktime != std::nullopt) merged_psbt.fallback_locktime = psbt.fallback_locktime;
    if (merged_psbt.m_tx_modifiable != std::nullopt && psbt.m_tx_modifiable != std::nullopt) *merged_psbt.m_tx_modifiable |= *psbt.m_tx_modifiable;
    if (merged_psbt.m_tx_modifiable == std::nullopt && psbt.m_tx_modifiable != std::nullopt) merged_psbt.m_tx_modifiable = psbt.m_tx_modifiable;
    if (contains_mweb && HasMWEBSignatureOrProof(merged_psbt)) ClearTxModifiable(merged_psbt);
    if (contains_mweb) {
        if (!MergeUnknownStrict(merged_psbt.unknown, psbt.unknown) ||
            !MergeProprietaryStrict(merged_psbt.m_proprietary, psbt.m_proprietary)) {
            return false;
        }
    } else {
        merged_psbt.unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
        merged_psbt.m_proprietary.insert(psbt.m_proprietary.begin(), psbt.m_proprietary.end());
    }

    *this = std::move(merged_psbt);

    return true;
}

TransactionError CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs)
{
    out = psbtxs[0]; // Copy the first one

    // Merge
    for (auto it = std::next(psbtxs.begin()); it != psbtxs.end(); ++it) {
        if (!out.Merge(*it)) {
            return TransactionError::PSBT_MISMATCH;
        }
    }
    return TransactionError::OK;
}
