// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <logging.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/SecretKeys.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <util/check.h>
#include <util/strencodings.h>

PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx, uint32_t version) : m_psbt_version(version)
{
    if (version == 0) {
        this->tx = tx;
    }

    SetupFromTx(tx);
}

bool PartiallySignedTransaction::IsNull() const
{
    return !tx && inputs.empty() && outputs.empty() && unknown.empty();
}

bool PartiallySignedTransaction::ContainsMWEBComponents() const noexcept
{
    if (tx.has_value() && !tx->mweb_tx.IsNull()) {
        return true;
    }

    if (mweb_tx_offset.has_value() || mweb_stealth_offset.has_value()) {
        return true;
    }

    if (!kernels.empty()) {
        return true;
    }

    for (const PSBTInput& input : inputs) {
        if (input.IsMWEB()) {
            return true;
        }
    }

    for (const PSBTOutput& output : outputs) {
        if (output.IsMWEB()) {
            return true;
        }
    }

    return false;
}

bool PartiallySignedTransaction::ComputeTimeLock(uint32_t& locktime) const
{
    std::optional<uint32_t> time_lock{0};
    std::optional<uint32_t> height_lock{0};
    for (const PSBTInput& input : inputs) {
        if (input.time_locktime != std::nullopt && input.height_locktime == std::nullopt) {
            height_lock.reset(); // Transaction can no longer have a height locktime
            if (time_lock == std::nullopt) {
                return false;
            }
        } else if (input.time_locktime == std::nullopt && input.height_locktime != std::nullopt) {
            time_lock.reset(); // Transaction can no longer have a time locktime
            if (height_lock == std::nullopt) {
                return false;
            }
        }
        if (input.time_locktime && time_lock != std::nullopt) {
            time_lock = std::max(time_lock, input.time_locktime);
        }
        if (input.height_locktime && height_lock != std::nullopt) {
            height_lock = std::max(height_lock, input.height_locktime);
        }
    }
    if (height_lock != std::nullopt && *height_lock > 0) {
        locktime = *height_lock;
        return true;
    }
    if (time_lock != std::nullopt && *time_lock > 0) {
        locktime = *time_lock;
        return true;
    }
    locktime = fallback_locktime.value_or(0);
    return true;
}

CMutableTransaction PartiallySignedTransaction::GetUnsignedTx() const
{
    if (tx != std::nullopt) {
        return *tx;
    }

    CMutableTransaction mtx;
    mtx.nVersion = tx_version;
    bool locktime_success = ComputeTimeLock(mtx.nLockTime);
    assert(locktime_success);
    uint32_t max_sequence = CTxIn::SEQUENCE_FINAL;
    for (const PSBTInput& input : inputs) {
        if (input.IsMWEB()) {
            mw::MutableInput mweb_input(*input.mweb_output_id);
            mweb_input.commitment = input.mweb_output_commit;
            mweb_input.output_pubkey = input.mweb_output_pubkey;
            mweb_input.amount = input.mweb_amount;
            if (input.mweb_shared_secret.has_value()) {
                mweb_input.raw_blind = mw::DeriveOutputRawBlind(*input.mweb_shared_secret);
            }
            mweb_input.features = input.mweb_features;
            mweb_input.extradata = input.mweb_extra_data;
            mweb_input.input_pubkey = input.mweb_input_pubkey;
            mweb_input.signature = input.mweb_sig;
            mweb_input.key_exchange_pubkey = input.mweb_key_exchange_pubkey;
            mweb_input.shared_secret = input.mweb_shared_secret;
            mtx.mweb_tx.inputs.push_back(std::move(mweb_input));
        } else {
            CTxIn txin;
            txin.prevout.hash = input.prev_txid;
            txin.prevout.n = *input.prev_out;
            txin.nSequence = input.sequence.value_or(max_sequence);
            mtx.vin.push_back(txin);
        }
    }

    for (const PSBTOutput& psbt_output : outputs) {
        if (psbt_output.IsMWEB()) {
            mw::MutableOutput mweb_output;
            mweb_output.commitment = psbt_output.mweb_commit;
            mweb_output.sender_pubkey = psbt_output.mweb_sender_pubkey;
            mweb_output.receiver_pubkey = psbt_output.mweb_output_pubkey;

            uint8_t features = 0;
            if (psbt_output.mweb_features.has_value()) {
                features = *psbt_output.mweb_features;
            } else {
                features |= psbt_output.mweb_standard_fields.has_value() ? mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT : 0;
                features |= psbt_output.mweb_extra_data.size() > 0 ? mw::OutputMessage::EXTRA_DATA_FEATURE_BIT : 0;
            }
            mweb_output.message = mw::OutputMessage(features, psbt_output.mweb_standard_fields, psbt_output.mweb_extra_data);

            mweb_output.proof = psbt_output.mweb_rangeproof;
            mweb_output.signature = psbt_output.mweb_sig;
            mweb_output.amount = psbt_output.amount;
            mweb_output.address = psbt_output.mweb_stealth_address;
            mtx.mweb_tx.outputs.push_back(std::move(mweb_output));
        } else {
            CTxOut txout;
            txout.nValue = *psbt_output.amount;
            txout.scriptPubKey = *psbt_output.script;
            mtx.vout.push_back(std::move(txout));
        }
    }

    for (const PSBTKernel& kernel : kernels) {
        mw::MutableKernel mut_kernel;
        mut_kernel.fee = kernel.fee;
        mut_kernel.pegin = kernel.pegin_amount;
        mut_kernel.SetPegOuts(kernel.pegouts);
        mut_kernel.lock_height = kernel.lock_height;
        mut_kernel.excess = kernel.commit;
        mut_kernel.stealth_excess = kernel.stealth_commit;
        mut_kernel.extradata = kernel.extra_data;
        mut_kernel.signature = kernel.sig;
        mtx.mweb_tx.kernels.push_back(std::move(mut_kernel));
    }

    mtx.mweb_tx.kernel_offset = mweb_tx_offset.value_or(BlindingFactor{});
    mtx.mweb_tx.stealth_offset = mweb_stealth_offset.value_or(BlindingFactor{});

    return mtx;
}

uint256 PartiallySignedTransaction::GetUniqueID() const
{
    if (GetPSBTVersion() == 0) {
        assert(tx != std::nullopt);
        return tx->GetHash();
    }

    // Get the unsigned transaction
    CMutableTransaction mtx = GetUnsignedTx();
    // Set the sequence numbers to 0
    for (CTxIn& txin : mtx.vin) {
        txin.nSequence = 0;
    }
    return mtx.GetHash();
}

bool PartiallySignedTransaction::AddInput(PSBTInput& psbtin)
{
    if (GetPSBTVersion() == 0) {
        // This is a v0 psbt, so do the v0 AddInput
        CTxIn txin(COutPoint(psbtin.prev_txid, *psbtin.prev_out));
        if (std::find(tx->vin.begin(), tx->vin.end(), txin) != tx->vin.end()) {
            // Prevent duplicate inputs
            return false;
        }
        tx->vin.push_back(txin);
        psbtin.partial_sigs.clear();
        psbtin.final_script_sig.clear();
        psbtin.final_script_witness.SetNull();
        inputs.push_back(psbtin);
        return true;
    } else if (GetPSBTVersion() >= 2) {
        if (psbtin.prev_txid.IsNull() || psbtin.prev_out == std::nullopt) {
            return false;
        }
        // Prevent duplicate inputs
        if (std::find_if(inputs.begin(), inputs.end(),
            [psbtin](const PSBTInput& psbt) {
                return psbt.prev_txid == psbtin.prev_txid && psbt.prev_out == psbtin.prev_out;
            }
        ) != inputs.end()) {
            return false;
        }

        // No global tx, must be PSBTv2.
        // Check inputs modifiable flag
        if (m_tx_modifiable == std::nullopt || !m_tx_modifiable->test(0)) {
            return false;
        }

        // Determine if we need to iterate the inputs.
        // For now, we only do this if the new input has a required time lock.
        // The BIP states that we should also do this if m_tx_modifiable's bit 2 is set
        // (Has SIGHASH_SINGLE flag) but since we are only adding inputs at the end of the vector,
        // we don't care about that.
        bool iterate_inputs = psbtin.time_locktime != std::nullopt || psbtin.height_locktime != std::nullopt;
        if (iterate_inputs) {
            uint32_t old_timelock;
            if (!ComputeTimeLock(old_timelock)) {
                return false;
            }

            std::optional<uint32_t> time_lock = psbtin.time_locktime;
            std::optional<uint32_t> height_lock = psbtin.height_locktime;
            bool has_sigs = false;
            for (const PSBTInput& input : inputs) {
                if (input.time_locktime != std::nullopt && input.height_locktime == std::nullopt) {
                    height_lock.reset(); // Transaction can no longer have a height locktime
                    if (time_lock == std::nullopt) {
                        return false;
                    }
                } else if (input.time_locktime == std::nullopt && input.height_locktime != std::nullopt) {
                    time_lock.reset(); // Transaction can no longer have a time locktime
                    if (height_lock == std::nullopt) {
                        return false;
                    }
                }
                if (input.time_locktime && time_lock != std::nullopt) {
                    time_lock = std::max(time_lock, input.time_locktime);
                }
                if (input.height_locktime && height_lock != std::nullopt) {
                    height_lock = std::max(height_lock, input.height_locktime);
                }
                if (!input.partial_sigs.empty()) {
                    has_sigs = true;
                }
            }
            uint32_t new_timelock = fallback_locktime.value_or(0);
            if (height_lock != std::nullopt && *height_lock > 0) {
                new_timelock = *height_lock;
            } else if (time_lock != std::nullopt && *time_lock > 0) {
                new_timelock = *time_lock;
            }
            if (has_sigs && old_timelock != new_timelock) {
                return false;
            }
        }

        // Add the input to the end
        inputs.push_back(psbtin);
        return true;
    }

    return false;
}

bool PartiallySignedTransaction::AddOutput(const PSBTOutput& psbtout)
{
    if (psbtout.amount == std::nullopt || !psbtout.script.has_value()) {
        return false;
    }

    if (tx != std::nullopt) {
        // This is a v0 psbt, do the v0 AddOutput
        CTxOut txout(*psbtout.amount, *psbtout.script);
        tx->vout.push_back(txout);
        outputs.push_back(psbtout);
        return true;
    }

    // No global tx, must be PSBTv2
    // Check outputs are modifiable
    if (m_tx_modifiable == std::nullopt || !m_tx_modifiable->test(1)) {
        return false;
    }
    outputs.push_back(psbtout);

    return true;
}

bool PSBTInput::GetUTXO(CTxOut& utxo) const
{
    if (non_witness_utxo) {
        if (prev_out >= non_witness_utxo->vout.size()) {
            return false;
        }
        if (non_witness_utxo->GetHash() != prev_txid) {
            return false;
        }
        utxo = non_witness_utxo->vout[*prev_out];
    } else if (!witness_utxo.IsNull()) {
        utxo = witness_utxo;
    } else {
        return false;
    }
    return true;
}

COutPoint PSBTInput::GetOutPoint() const
{
    return COutPoint(prev_txid, *prev_out);
}

bool PartiallySignedTransaction::IsComplete() const noexcept
{
    const bool is_mweb = ContainsMWEBComponents();
    if (is_mweb && kernels.empty()) {
        return false;
    }

    for (const PSBTInput& input : inputs) {
        if (!PSBTInputSigned(input)) {
            return false;
        }

        if (input.IsMWEB()) {
            if (!input.mweb_features || !input.mweb_output_commit || !input.mweb_output_pubkey) {
                return false;
            }
            const uint8_t features = *input.mweb_features;
            if (features & mw::Input::STEALTH_KEY_FEATURE_BIT && !input.mweb_input_pubkey) {
                return false;
            } else if (features & mw::Input::EXTRA_DATA_FEATURE_BIT && input.mweb_extra_data.empty()) {
                return false;
            }
        }
    }

    for (const PSBTKernel& kernel : kernels) {
        if (!kernel.commit || !kernel.features || !kernel.sig) {
            return false;
        }

        const uint8_t features = *kernel.features;
        if (features & mw::Kernel::FEE_FEATURE_BIT && !kernel.fee) {
            return false;
        } else if (features & mw::Kernel::PEGIN_FEATURE_BIT && !kernel.pegin_amount) {
            return false;
        } else if (features & mw::Kernel::PEGOUT_FEATURE_BIT && kernel.pegouts.empty()) {
            return false;
        } else if (features & mw::Kernel::HEIGHT_LOCK_FEATURE_BIT && !kernel.lock_height) {
            return false;
        } else if (features & mw::Kernel::STEALTH_EXCESS_FEATURE_BIT && !kernel.stealth_commit) {
            return false;
        } else if (features & mw::Kernel::EXTRA_DATA_FEATURE_BIT && kernel.extra_data.empty()) {
            return false;
        }
    }

    for (const PSBTOutput& output : outputs) {
        if (output.IsMWEB()) {
            if (!output.mweb_commit || !output.mweb_features || !output.mweb_sender_pubkey || !output.mweb_output_pubkey || !output.mweb_rangeproof || !output.mweb_sig) {
                return false;
            }
            
            const uint8_t features = *output.mweb_features;
            if (features & mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT && !output.mweb_standard_fields) {
                return false;
            } else if (features & mw::OutputMessage::EXTRA_DATA_FEATURE_BIT && output.mweb_extra_data.empty()) {
                return false;
            }
        }
    }

    if (is_mweb && (!mweb_tx_offset.has_value() || !mweb_stealth_offset.has_value())) {
        return false;
    }

    return true;
}

bool PSBTInput::IsNull() const
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty() && hd_keypaths.empty() && redeem_script.empty() && witness_script.empty() && !mweb_output_id.has_value();
}

void PSBTInput::FillSignatureData(SignatureData& sigdata) const
{
    if (!final_script_sig.empty()) {
        sigdata.scriptSig = final_script_sig;
        sigdata.complete = true;
    }
    if (!final_script_witness.IsNull()) {
        sigdata.scriptWitness = final_script_witness;
        sigdata.complete = true;
    }
    if (sigdata.complete) {
        return;
    }

    sigdata.signatures.insert(partial_sigs.begin(), partial_sigs.end());
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_key_sig.empty()) {
        sigdata.taproot_key_path_sig = m_tap_key_sig;
    }
    for (const auto& [pubkey_leaf, sig] : m_tap_script_sigs) {
        sigdata.taproot_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!m_tap_internal_key.IsNull()) {
        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
    }
    if (!m_tap_merkle_root.IsNull()) {
        sigdata.tr_spenddata.merkle_root = m_tap_merkle_root;
    }
    for (const auto& [leaf_script, control_block] : m_tap_scripts) {
        sigdata.tr_spenddata.scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
    }
}

void PSBTInput::FromSignatureData(const SignatureData& sigdata)
{
    if (sigdata.complete) {
        partial_sigs.clear();
        hd_keypaths.clear();
        redeem_script.clear();
        witness_script.clear();

        if (!sigdata.scriptSig.empty()) {
            final_script_sig = sigdata.scriptSig;
        }
        if (!sigdata.scriptWitness.IsNull()) {
            final_script_witness = sigdata.scriptWitness;
        }
        return;
    }

    partial_sigs.insert(sigdata.signatures.begin(), sigdata.signatures.end());
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.taproot_key_path_sig.empty()) {
        m_tap_key_sig = sigdata.taproot_key_path_sig;
    }
    for (const auto& [pubkey_leaf, sig] : sigdata.taproot_script_sigs) {
        m_tap_script_sigs.emplace(pubkey_leaf, sig);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (!sigdata.tr_spenddata.merkle_root.IsNull()) {
        m_tap_merkle_root = sigdata.tr_spenddata.merkle_root;
    }
    for (const auto& [leaf_script, control_block] : sigdata.tr_spenddata.scripts) {
        m_tap_scripts.emplace(leaf_script, control_block);
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
}

void PSBTOutput::FillSignatureData(SignatureData& sigdata) const
{
    if (!redeem_script.empty()) {
        sigdata.redeem_script = redeem_script;
    }
    if (!witness_script.empty()) {
        sigdata.witness_script = witness_script;
    }
    for (const auto& key_pair : hd_keypaths) {
        sigdata.misc_pubkeys.emplace(key_pair.first.GetID(), key_pair);
    }
    if (!m_tap_tree.empty() && m_tap_internal_key.IsFullyValid()) {
        TaprootBuilder builder;
        for (const auto& [depth, leaf_ver, script] : m_tap_tree) {
            builder.Add((int)depth, script, (int)leaf_ver, /*track=*/true);
        }
        assert(builder.IsComplete());
        builder.Finalize(m_tap_internal_key);
        TaprootSpendData spenddata = builder.GetSpendData();

        sigdata.tr_spenddata.internal_key = m_tap_internal_key;
        sigdata.tr_spenddata.Merge(spenddata);
    }
    for (const auto& [pubkey, leaf_origin] : m_tap_bip32_paths) {
        sigdata.taproot_misc_pubkeys.emplace(pubkey, leaf_origin);
    }
}

void PSBTOutput::FromSignatureData(const SignatureData& sigdata)
{
    if (redeem_script.empty() && !sigdata.redeem_script.empty()) {
        redeem_script = sigdata.redeem_script;
    }
    if (witness_script.empty() && !sigdata.witness_script.empty()) {
        witness_script = sigdata.witness_script;
    }
    for (const auto& entry : sigdata.misc_pubkeys) {
        hd_keypaths.emplace(entry.second);
    }
    if (!sigdata.tr_spenddata.internal_key.IsNull()) {
        m_tap_internal_key = sigdata.tr_spenddata.internal_key;
    }
    if (sigdata.tr_builder.has_value() && sigdata.tr_builder->HasScripts()) {
        m_tap_tree = sigdata.tr_builder->GetTreeTuples();
    }
    for (const auto& [pubkey, leaf_origin] : sigdata.taproot_misc_pubkeys) {
        m_tap_bip32_paths.emplace(pubkey, leaf_origin);
    }
}

bool PSBTOutput::IsNull() const
{
    return redeem_script.empty() && witness_script.empty() && hd_keypaths.empty() && unknown.empty() && !mweb_stealth_address.has_value() && !mweb_commit.has_value();
}

bool PSBTInputSigned(const PSBTInput& input)
{
    return !input.final_script_sig.empty() || !input.final_script_witness.IsNull() || input.mweb_sig.has_value();
}

static bool VerifyMWEBPSBTInputSignature(const PSBTInput& input)
{
    if (!input.mweb_sig.has_value() || !input.mweb_output_id.has_value() || !input.mweb_output_pubkey.has_value() || !input.mweb_features.has_value()) {
        return false;
    }

    const uint8_t features = *input.mweb_features;
    if ((features & mw::Input::STEALTH_KEY_FEATURE_BIT) != 0 && !input.mweb_input_pubkey.has_value()) {
        return false;
    }
    if ((features & mw::Input::EXTRA_DATA_FEATURE_BIT) != 0 && input.mweb_extra_data.empty()) {
        return false;
    }

    Hasher msg_hasher;
    msg_hasher << features << *input.mweb_output_id;
    if ((features & mw::Input::EXTRA_DATA_FEATURE_BIT) != 0) {
        msg_hasher << input.mweb_extra_data;
    }
    const mw::Hash msg_hash = msg_hasher.hash();

    PublicKey public_key = *input.mweb_output_pubkey;
    if ((features & mw::Input::STEALTH_KEY_FEATURE_BIT) != 0) {
        Hasher key_hasher;
        key_hasher << *input.mweb_input_pubkey << *input.mweb_output_pubkey;
        const SecretKey key_hash = key_hasher.hash();

        public_key = public_key.Mul(key_hash).Add(*input.mweb_input_pubkey);
    }

    return Schnorr::Verify(*input.mweb_sig, public_key, msg_hash);
}

bool PSBTInputSignedAndVerified(const PartiallySignedTransaction& psbt, unsigned int input_index, const PrecomputedTransactionData* txdata)
{
    assert(psbt.inputs.size() >= input_index);
    const PSBTInput& input = psbt.inputs[input_index];

    if (input.mweb_sig.has_value()) {
        return VerifyMWEBPSBTInputSignature(input);
    }

    CTxOut utxo;
    if (!input.GetUTXO(utxo)) {
        return false;
    }

    const CMutableTransaction tx = psbt.GetUnsignedTx();
    if (txdata) {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, *txdata, MissingDataBehavior::FAIL});
    } else {
        return VerifyScript(input.final_script_sig, utxo.scriptPubKey, &input.final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker{&tx, input_index, utxo.nValue, MissingDataBehavior::FAIL});
    }
}

static bool VerifyPSBTInputSignatures(const PartiallySignedTransaction& psbt, const PrecomputedTransactionData* txdata)
{
    for (unsigned int i = 0; i < psbt.inputs.size(); ++i) {
        if (!PSBTInputSignedAndVerified(psbt, i, txdata)) {
            return false;
        }
    }

    return true;
}

static bool VerifyFinalMWEBTransaction(const CMutableTransaction& mtx)
{
    if (mtx.mweb_tx.IsNull()) {
        return true;
    }

    const CTransaction tx{mtx};
    if (tx.mweb_tx.IsNull()) {
        return false;
    }

    return !tx.mweb_tx.m_transaction->Validate();
}

size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt) {
    size_t count = 0;
    for (const auto& input : psbt.inputs) {
        if (!PSBTInputSigned(input)) {
            count++;
        }
    }

    return count;
}

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index)
{
    CMutableTransaction tx = psbt.GetUnsignedTx();
    PSBTOutput& psbt_out = psbt.outputs.at(index);
    if (psbt_out.IsMWEB()) {
        return;
    }

    const CTxOut& out = tx.vout.at(index);

    // Fill a SignatureData with output info
    SignatureData sigdata;
    psbt_out.FillSignatureData(sigdata);

    // Construct a would-be spend of this output, to update sigdata with.
    // Note that ProduceSignature is used to fill in metadata (not actual signatures),
    // so provider does not need to provide any private keys (it can be a HidingSigningProvider).
    MutableTransactionSignatureCreator creator(tx, /*input_idx=*/0, out.nValue, SIGHASH_ALL);
    ProduceSignature(provider, creator, out.scriptPubKey, sigdata);

    // Put redeem_script, witness_script, key paths, into PSBTOutput.
    psbt_out.FromSignatureData(sigdata);
}

PrecomputedTransactionData PrecomputePSBTData(const PartiallySignedTransaction& psbt)
{

    const CMutableTransaction& tx = psbt.GetUnsignedTx();
    bool have_all_spent_outputs = true;
    std::vector<CTxOut> utxos;
    for (const PSBTInput& input : psbt.inputs) {
        if (input.IsMWEB()) continue;
        if (!input.GetUTXO(utxos.emplace_back())) have_all_spent_outputs = false;
    }

    PrecomputedTransactionData txdata;
    if (have_all_spent_outputs) {
        txdata.Init(tx, std::move(utxos), true);
    } else {
        txdata.Init(tx, {}, true);
    }
    return txdata;
}

bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, int sighash,  SignatureData* out_sigdata, bool finalize)
{
    PSBTInput& input = psbt.inputs.at(index);
    const CMutableTransaction& tx = psbt.GetUnsignedTx();

    if (PSBTInputSignedAndVerified(psbt, index, txdata)) {
        return true;
    }

    // Fill SignatureData with input info
    SignatureData sigdata;
    input.FillSignatureData(sigdata);

    // Get UTXO
    bool require_witness_sig = false;
    CTxOut utxo;

    if (input.non_witness_utxo) {
        // If we're taking our information from a non-witness UTXO, verify that it matches the prevout.
        COutPoint prevout = input.GetOutPoint();
        if (prevout.n >= input.non_witness_utxo->vout.size()) {
            return false;
        }
        if (input.non_witness_utxo->GetHash() != prevout.hash) {
            return false;
        }
        utxo = input.non_witness_utxo->vout[prevout.n];
    } else if (!input.witness_utxo.IsNull()) {
        utxo = input.witness_utxo;
        // When we're taking our information from a witness UTXO, we can't verify it is actually data from
        // the output being spent. This is safe in case a witness signature is produced (which includes this
        // information directly in the hash), but not for non-witness signatures. Remember that we require
        // a witness signature in this situation.
        require_witness_sig = true;
    } else {
        return false;
    }

    sigdata.witness = false;
    bool sig_complete;
    if (txdata == nullptr) {
        sig_complete = ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, utxo.scriptPubKey, sigdata);
    } else {
        MutableTransactionSignatureCreator creator(tx, index, utxo.nValue, txdata, sighash);
        sig_complete = ProduceSignature(provider, creator, utxo.scriptPubKey, sigdata);
    }
    // Verify that a witness signature was produced in case one was required.
    if (require_witness_sig && !sigdata.witness) return false;

    // If we are not finalizing, set sigdata.complete to false to not set the scriptWitness
    if (!finalize && sigdata.complete) sigdata.complete = false;

    input.FromSignatureData(sigdata);

    // If we have a witness signature, put a witness UTXO.
    if (sigdata.witness) {
        input.witness_utxo = utxo;
        // We can remove the non_witness_utxo if and only if there are no non-segwit or segwit v0
        // inputs in this transaction. Since this requires inspecting the entire transaction, this
        // is something for the caller to deal with (i.e. FillPSBT).
    }

    // Fill in the missing info
    if (out_sigdata) {
        out_sigdata->missing_pubkeys = sigdata.missing_pubkeys;
        out_sigdata->missing_sigs = sigdata.missing_sigs;
        out_sigdata->missing_redeem_script = sigdata.missing_redeem_script;
        out_sigdata->missing_witness_script = sigdata.missing_witness_script;
    }

    return sig_complete;
}

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx, const int& sighash_type)
{
    // Only drop non_witness_utxos if sighash_type != SIGHASH_ANYONECANPAY
    if ((sighash_type & 0x80) != SIGHASH_ANYONECANPAY) {

        // Figure out if any non_witness_utxos should be dropped
        std::vector<unsigned int> to_drop;
        for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
            const auto& input = psbtx.inputs.at(i);
            int wit_ver;
            std::vector<unsigned char> wit_prog;
            if (input.witness_utxo.IsNull() || !input.witness_utxo.scriptPubKey.IsWitnessProgram(wit_ver, wit_prog)) {
                // There's a non-segwit input or Segwit v0, so we cannot drop any witness_utxos
                to_drop.clear();
                break;
            }
            if (wit_ver == 0) {
                // Segwit v0, so we cannot drop any non_witness_utxos
                to_drop.clear();
                break;
            }
            if (input.non_witness_utxo) {
                to_drop.push_back(i);
            }
        }

        // Drop the non_witness_utxos that we can drop
        for (unsigned int i : to_drop) {
            psbtx.inputs.at(i).non_witness_utxo = nullptr;
        }
    }
}

util::Result<CMutableTransaction> FinalizePSBT(PartiallySignedTransaction& psbtx)
{
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        complete &= SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, SIGHASH_ALL, nullptr, true);
    }

    if (!complete || !psbtx.IsComplete() || !VerifyPSBTInputSignatures(psbtx, &txdata) || !VerifyPeginOutputs(psbtx, /*require_final=*/true)) {
        return util::Error{};
    }

    CMutableTransaction mtx = psbtx.GetUnsignedTx();
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        mtx.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
        mtx.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
    }

    if (!VerifyFinalMWEBTransaction(mtx)) {
        return util::Error{};
    }

    return mtx;
}

std::string PSBTRoleName(PSBTRole role) {
    switch (role) {
    case PSBTRole::CREATOR: return "creator";
    case PSBTRole::UPDATER: return "updater";
    case PSBTRole::SIGNER: return "signer";
    case PSBTRole::FINALIZER: return "finalizer";
    case PSBTRole::EXTRACTOR: return "extractor";
        // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

bool DecodeBase64PSBT(PartiallySignedTransaction& psbt, const std::string& base64_tx, std::string& error)
{
    auto tx_data = DecodeBase64(base64_tx);
    if (!tx_data) {
        error = "invalid base64";
        return false;
    }
    return DecodeRawPSBT(psbt, MakeByteSpan(*tx_data), error);
}

bool DecodeRawPSBT(PartiallySignedTransaction& psbt, Span<const std::byte> tx_data, std::string& error)
{
    CDataStream ss_data(tx_data, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ss_data >> psbt;
        if (!ss_data.empty()) {
            error = "extra data after PSBT";
            return false;
        }
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    return true;
}

uint32_t PartiallySignedTransaction::GetPSBTVersion() const
{
    return m_psbt_version;
}

void PartiallySignedTransaction::SetupFromTx(const CMutableTransaction& tx)
{
    tx_version = tx.nVersion;
    fallback_locktime = tx.nLockTime;

    size_t num_inputs = tx.vin.size() + tx.mweb_tx.inputs.size();
    size_t num_outputs = tx.vout.size() + tx.mweb_tx.outputs.size();
    size_t num_kernels = tx.mweb_tx.kernels.size();

    inputs.resize(num_inputs, PSBTInput(GetPSBTVersion()));
    outputs.resize(num_outputs, PSBTOutput(GetPSBTVersion()));
    kernels.resize(num_kernels, PSBTKernel());

    for (uint32_t i = 0; i < tx.vin.size(); ++i) {
        PSBTInput& psbt_input = inputs[i];
        const CTxIn& txin = tx.vin.at(i);

        psbt_input.prev_txid = txin.prevout.hash;
        psbt_input.prev_out = txin.prevout.n;
        psbt_input.sequence = txin.nSequence;
    }

    for (uint32_t i = 0; i < tx.mweb_tx.inputs.size(); i++) {
        PSBTInput& psbt_input = inputs[i + tx.vin.size()];
        const mw::MutableInput& mweb_input = tx.mweb_tx.inputs[i];

        psbt_input.mweb_output_id = mweb_input.output_id;
        psbt_input.mweb_output_commit = mweb_input.commitment;
        psbt_input.mweb_output_pubkey = mweb_input.output_pubkey;
        psbt_input.mweb_input_pubkey = mweb_input.input_pubkey;
        psbt_input.mweb_features = mweb_input.features;
        psbt_input.mweb_sig = mweb_input.signature;
        psbt_input.mweb_amount = mweb_input.amount;
        psbt_input.mweb_extra_data = mweb_input.extradata;
    }

    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        PSBTOutput& psbt_output = outputs[i];
        const CTxOut& txout = tx.vout.at(i);

        psbt_output.amount = txout.nValue;
        psbt_output.script = txout.scriptPubKey;
    }

    for (uint32_t i = 0; i < tx.mweb_tx.outputs.size(); i++) {
        PSBTOutput& psbt_output = outputs[i + tx.vout.size()];
        const mw::MutableOutput& mweb_output = tx.mweb_tx.outputs[i];

        psbt_output.mweb_stealth_address = mweb_output.address;
        psbt_output.amount = mweb_output.amount;

        psbt_output.mweb_commit = mweb_output.commitment;
        if (mweb_output.message.has_value()) {
            psbt_output.mweb_features = mweb_output.message->features;
        }
        psbt_output.mweb_sender_pubkey = mweb_output.sender_pubkey;
        psbt_output.mweb_output_pubkey = mweb_output.receiver_pubkey;
        if (mweb_output.message.has_value()) {
            psbt_output.mweb_standard_fields = mweb_output.message->standard_fields;
            psbt_output.mweb_extra_data = mweb_output.message->extra_data;
        }
        psbt_output.mweb_rangeproof = mweb_output.proof;
        psbt_output.mweb_sig = mweb_output.signature;
    }

    for (uint32_t i = 0; i < tx.mweb_tx.kernels.size(); i++) {
        PSBTKernel& psbt_kernel = kernels[i];
        const mw::MutableKernel& mweb_kernel = tx.mweb_tx.kernels[i];
        psbt_kernel.features = mweb_kernel.CalcFeatureByte();
        psbt_kernel.commit = mweb_kernel.excess;
        psbt_kernel.stealth_commit = mweb_kernel.stealth_excess;
        psbt_kernel.fee = mweb_kernel.fee;
        psbt_kernel.pegin_amount = mweb_kernel.pegin;
        psbt_kernel.pegouts = mweb_kernel.GetPegOuts();
        psbt_kernel.lock_height = mweb_kernel.lock_height;
        psbt_kernel.extra_data = mweb_kernel.extradata;
        psbt_kernel.sig = mweb_kernel.signature;
    }
}
