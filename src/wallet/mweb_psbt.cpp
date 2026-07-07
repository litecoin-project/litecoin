// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/mweb_psbt.h>

#include <key.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/wallet/Keychain.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <util/translation.h>

namespace {

//! Fill in missing input spend keys from the resolved key map.
void ApplyResolvedSpendKeys(mw::MutableTx& mweb_tx, const std::unordered_map<mw::Hash, SecretKey>& spend_keys)
{
    for (mw::MutableInput& input : mweb_tx.inputs) {
        if (input.spend_key.has_value()) {
            continue;
        }

        auto spend_iter = spend_keys.find(input.output_id);
        if (spend_iter != spend_keys.end()) {
            input.spend_key = spend_iter->second;
        }
    }
}

//! Write the signed MWEB transaction back into the PSBT's input/output/kernel
//! fields, peg-in output scripts, and global offsets.
void CommitMWEBTxToPSBT(PartiallySignedTransaction& psbtx, const CMutableTransaction& mtx)
{
    if (psbtx.m_tx_modifiable.has_value()) {
        psbtx.m_tx_modifiable->reset();
    }

    size_t idx = 0;
    for (PSBTInput& psbt_input : psbtx.inputs) {
        if (!psbt_input.IsMWEB()) {
            continue;
        }

        const mw::MutableInput& input = mtx.mweb_tx.inputs[idx++];
        if (!psbt_input.mweb_output_id.has_value()) {
            psbt_input.mweb_output_id = input.output_id;
        }
        if (!psbt_input.mweb_output_commit.has_value()) {
            psbt_input.mweb_output_commit = input.commitment;
        }
        if (!psbt_input.mweb_output_pubkey.has_value()) {
            psbt_input.mweb_output_pubkey = input.output_pubkey;
        }
        psbt_input.mweb_input_pubkey = input.input_pubkey;
        psbt_input.mweb_features = input.features;
        psbt_input.mweb_sig = input.signature;
        psbt_input.mweb_amount = input.amount;
        psbt_input.mweb_extra_data = input.extradata;
    }

    idx = 0;
    for (PSBTOutput& psbt_output : psbtx.outputs) {
        if (!psbt_output.IsMWEB()) {
            continue;
        }

        const mw::MutableOutput& output = mtx.mweb_tx.outputs[idx++];
        psbt_output.amount = output.amount;
        psbt_output.mweb_stealth_address = output.address;
        psbt_output.mweb_commit = output.commitment;
        psbt_output.mweb_sender_pubkey = output.sender_pubkey;
        psbt_output.mweb_output_pubkey = output.receiver_pubkey;
        assert(output.message.has_value());
        psbt_output.mweb_features = output.message->features;
        psbt_output.mweb_standard_fields = output.message->standard_fields;
        psbt_output.mweb_extra_data = output.message->extra_data;
        psbt_output.mweb_rangeproof = output.proof;
        psbt_output.mweb_sig = output.signature;
    }

    if (psbtx.kernels.size() < mtx.mweb_tx.kernels.size()) {
        psbtx.kernels.resize(mtx.mweb_tx.kernels.size());
    }

    idx = 0;
    for (const mw::MutableKernel& kernel : mtx.mweb_tx.kernels) {
        PSBTKernel& psbt_kernel = psbtx.kernels[idx++];
        psbt_kernel.features = kernel.CalcFeatureByte();
        psbt_kernel.commit = kernel.excess;
        psbt_kernel.stealth_commit = kernel.stealth_excess;
        psbt_kernel.fee = kernel.fee;
        psbt_kernel.pegin_amount = kernel.pegin;
        psbt_kernel.pegouts = kernel.GetPegOuts();
        psbt_kernel.lock_height = kernel.lock_height;
        psbt_kernel.extra_data = kernel.extradata;
        psbt_kernel.sig = kernel.signature;
    }

    for (size_t i = 0; i < mtx.vout.size(); i++) {
        const CTxOut& out = mtx.vout[i];
        if (out.scriptPubKey.IsMWEBPegin()) {
            PSBTOutput& psbt_output = psbtx.outputs[i];
            psbt_output.amount = out.nValue;
            psbt_output.script = out.scriptPubKey;
        }
    }

    psbtx.mweb_tx_offset = mtx.mweb_tx.kernel_offset.IsNull() ? std::nullopt : std::make_optional(mtx.mweb_tx.kernel_offset);
    psbtx.mweb_stealth_offset = mtx.mweb_tx.stealth_offset.IsNull() ? std::nullopt : std::make_optional(mtx.mweb_tx.stealth_offset);
}

//! Resolve the keychain for an input, preferring the coin's known master scan
//! key over one recovered from the descriptor's scan secret.
mw::Keychain::Ptr ResolveKeychain(const MWEBSigningKeyStore& keystore, const std::optional<mw::WalletCoin>& coin, const std::optional<MWEBAddressDescriptorData>& descriptor_data)
{
    if (coin && coin->master_scan_key_id.has_value()) {
        return keystore.GetKeychain(coin->master_scan_key_id.value());
    }
    if (descriptor_data && descriptor_data->scan_secret) {
        return keystore.GetKeychain(PublicKey::From(*descriptor_data->scan_secret).GetID());
    }
    return nullptr;
}

//! Resolve the input's shared secret: from the input's own field, then the
//! wallet coin, then by ECDH from the key-exchange pubkey and a scan secret.
std::optional<SecretKey> ResolveSharedSecret(const PSBTInput& input, const std::optional<mw::WalletCoin>& coin, const mw::Keychain::Ptr& keychain, const std::optional<MWEBAddressDescriptorData>& descriptor_data)
{
    if (input.mweb_shared_secret) {
        return input.mweb_shared_secret;
    }
    if (coin && coin->shared_secret.has_value()) {
        return coin->shared_secret;
    }

    if (input.mweb_key_exchange_pubkey.has_value()) {
        std::optional<SecretKey> scan_secret;
        if (keychain) {
            scan_secret = keychain->GetScanSecret();
        } else if (descriptor_data && descriptor_data->scan_secret) {
            scan_secret = descriptor_data->scan_secret;
        }
        if (scan_secret) {
            return mw::RecoverSharedSecret(*input.mweb_key_exchange_pubkey, *scan_secret);
        }
    }

    return std::nullopt;
}

//! Resolve the input's spend key: from the wallet coin, then from the
//! descriptor's private keys, then from the keychain by address index.
std::optional<SecretKey> ResolveSpendKey(const PSBTInput& input, const std::optional<mw::WalletCoin>& coin, const mw::Keychain::Ptr& keychain, const std::optional<MWEBAddressDescriptorData>& descriptor_data, const std::optional<SecretKey>& shared_secret)
{
    if (coin && coin->spend_key) {
        return coin->spend_key;
    }
    if (descriptor_data && descriptor_data->subaddress_spend_secret && shared_secret) {
        return mw::DeriveOutputSpendKey(*descriptor_data->subaddress_spend_secret, *shared_secret);
    }
    if (!shared_secret || !keychain) {
        return std::nullopt;
    }

    std::optional<uint32_t> address_index;
    if (coin && coin->address_index != mw::UNKNOWN_INDEX && coin->address_index != mw::CUSTOM_KEY) {
        address_index = coin->address_index;
    }

    if (!address_index && descriptor_data) {
        address_index = keychain->LookupAddressIndex(descriptor_data->address);
    }

    if (!address_index && input.mweb_output_pubkey.has_value()) {
        StealthAddress address = mw::RecoverSubaddress(*input.mweb_output_pubkey, *shared_secret, keychain->GetScanSecret());
        address_index = keychain->LookupAddressIndex(address);
    }

    if (address_index) {
        return mw::DeriveOutputSpendKey(keychain->GetSubaddressSpendKey(*address_index), *shared_secret);
    }
    return std::nullopt;
}

} // namespace

util::Result<MWEBAddressDescriptorData> ParseMWEBAddressDescriptor(const std::string& descriptor_str)
{
    FlatSigningProvider keys;
    std::string error;
    std::unique_ptr<Descriptor> descriptor = Parse(descriptor_str, keys, error, /*require_checksum=*/false);
    if (!descriptor) {
        return util::Error{Untranslated(strprintf("Invalid MWEB address descriptor: %s", error))};
    }
    if (descriptor->GetOutputType() != OutputType::MWEB) {
        return util::Error{Untranslated("MWEB address descriptor has wrong output type")};
    }
    if (descriptor->IsRange()) {
        return util::Error{Untranslated("MWEB address descriptor must be single-address")};
    }

    std::vector<GenericAddress> outputs;
    FlatSigningProvider expanded;
    if (!descriptor->Expand(0, keys, outputs, expanded) || outputs.size() != 1 || !outputs[0].IsMWEB()) {
        return util::Error{Untranslated("MWEB address descriptor did not expand to one MWEB address")};
    }

    MWEBAddressDescriptorData data;
    data.address = outputs[0].GetMWEBAddress();

    CKey scan_key;
    if (expanded.GetMWEBMasterScanKey(scan_key) || keys.GetMWEBMasterScanKey(scan_key)) {
        data.scan_secret = SecretKey(scan_key.begin());
    }

    FlatSigningProvider private_keys;
    descriptor->ExpandPrivate(0, keys, private_keys);

    CKey subaddress_spend_key;
    const CKeyID subaddress_spend_keyid = data.address.GetSpendPubKey().GetID();
    if (private_keys.GetKey(subaddress_spend_keyid, subaddress_spend_key)) {
        data.subaddress_spend_secret = SecretKey(subaddress_spend_key.begin());
    }

    return data;
}

util::Result<std::optional<SecretKey>> ResolveMWEBInputKeys(PSBTInput& input, const MWEBSigningKeyStore& keystore)
{
    assert(input.IsMWEB());

    const std::optional<mw::WalletCoin> coin = keystore.GetWalletCoin(*input.mweb_output_id);

    if (!input.mweb_address_descriptor && coin) {
        input.mweb_address_descriptor = keystore.InferAddressDescriptor(*coin);
    }

    std::optional<MWEBAddressDescriptorData> descriptor_data;
    if (input.mweb_address_descriptor) {
        util::Result<MWEBAddressDescriptorData> parsed_descriptor = ParseMWEBAddressDescriptor(*input.mweb_address_descriptor);
        if (!parsed_descriptor) {
            return util::Error{util::ErrorString(parsed_descriptor)};
        }
        descriptor_data = std::move(parsed_descriptor.value());
    }

    const mw::Keychain::Ptr keychain = ResolveKeychain(keystore, coin, descriptor_data);
    const std::optional<SecretKey> shared_secret = ResolveSharedSecret(input, coin, keychain, descriptor_data);

    if (descriptor_data && descriptor_data->scan_secret && shared_secret && input.mweb_output_pubkey) {
        // Check that the address derivable from the input's output pubkey and shared secret matches the address the descriptor claims the input belongs to.
        const StealthAddress input_address = mw::RecoverSubaddress(*input.mweb_output_pubkey, *shared_secret, *descriptor_data->scan_secret);
        if (input_address != descriptor_data->address) {
            return util::Error{Untranslated("MWEB address descriptor does not match input's output pubkey")};
        }
    }

    if (shared_secret) {
        input.mweb_shared_secret = shared_secret;
    }

    return ResolveSpendKey(input, coin, keychain, descriptor_data, shared_secret);
}

util::Result<MWEBSignOutcome> SignPSBTMWEBComponents(PartiallySignedTransaction& psbtx, const std::unordered_map<mw::Hash, SecretKey>& spend_keys, const SecretKey& rewind_key, const mw::SenderKeyGenerator& generate_sender_key)
{
    CMutableTransaction mtx = psbtx.GetUnsignedTx();
    ApplyResolvedSpendKeys(mtx.mweb_tx, spend_keys);

    // mw::SignTx may rewrite peg-in scriptPubKeys in mtx.vout.
    // Any precomputed sighash data from before this point must be discarded.
    util::Result<mw::SignTxResult> mweb_result = mw::SignTx(mtx, rewind_key, generate_sender_key);
    if (!mweb_result) {
        return util::Error{util::ErrorString(mweb_result)};
    }

    CommitMWEBTxToPSBT(psbtx, mtx);

    return MWEBSignOutcome{std::move(mweb_result->wallet_coins_by_output_id)};
}
