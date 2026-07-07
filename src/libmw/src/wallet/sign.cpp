#include <mw/wallet/sign.h>
#include <mw/crypto/Blinds.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/OutputMask.h>
#include <script/standard.h>

#include <vector>

MW_NAMESPACE

static util::Result<Signature> InputSignature(
    const mw::Hash& output_id,
    const uint8_t features,
    const SecretKey& input_key,
    const SecretKey& output_key,
    const std::vector<uint8_t>& extra_data) noexcept
{
    try {
        PublicKey input_pubkey = PublicKey::From(input_key);
        PublicKey output_pubkey = PublicKey::From(output_key);

        // Hash keys (K_i||K_o)
        Hasher key_hasher;
        key_hasher << input_pubkey << output_pubkey;
        SecretKey key_hash = SecretKey::FromHash(key_hasher.hash());

        // Calculate aggregated key k_agg = k_i + HASH(K_i||K_o) * k_o
        SecretKey sig_key = SecretKeys::From(output_key)
                                .Mul(key_hash)
                                .Add(input_key)
                                .Total();

        // Hash message
        Hasher msg_hasher;
        msg_hasher << features << output_id;
        if (features & mw::Input::FeatureBit::EXTRA_DATA_FEATURE_BIT) {
            msg_hasher << extra_data;
        }
        mw::Hash msg_hash = msg_hasher.hash();

        return Schnorr::Sign(sig_key.data(), msg_hash);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(e.what())};
    }
}

struct SignInputResult
{
    BlindingFactor input_blind{};
    SecretKey ephemeral_key{};
    SecretKey spend_key{};
};

static util::Result<SignInputResult> SignInput(MutableInput& input) noexcept
{
    if (input.signature.has_value()) {
        return util::Error{Untranslated("Input is already signed")};
    }

    if (!input.raw_blind) {
        if (input.shared_secret) {
            input.raw_blind = mw::DeriveOutputRawBlind(*input.shared_secret);
        } else {
            return util::Error{Untranslated("Input blinding factor and shared secret missing")};
        }
    }

    if (!input.spend_key) {
        return util::Error{Untranslated("Input spend key missing")};
    }

    if (!input.amount) {
        return util::Error{Untranslated("Input amount missing")};
    }

    input.output_pubkey = PublicKey::From(*input.spend_key);

    if (!input.features) {
        input.features = static_cast<uint8_t>(
            mw::Input::FeatureBit::STEALTH_KEY_FEATURE_BIT |
            (input.extradata.empty() ? 0 : mw::Input::FeatureBit::EXTRA_DATA_FEATURE_BIT));
    } else if (!input.extradata.empty()) {
        input.features = static_cast<uint8_t>(*input.features | mw::Input::FeatureBit::EXTRA_DATA_FEATURE_BIT);
    }

    if ((*input.features & mw::Input::FeatureBit::EXTRA_DATA_FEATURE_BIT) > 0 && input.extradata.empty()) {
        return util::Error{Untranslated("Input extra data missing")};
    }

    if ((*input.features & mw::Input::FeatureBit::STEALTH_KEY_FEATURE_BIT) > 0) {
        if (!input.ephemeral_key) {
            input.ephemeral_key = SecretKey::Random();
        }
        input.input_pubkey = PublicKey::From(*input.ephemeral_key);
    } else {
        input.ephemeral_key = std::nullopt;
        input.input_pubkey = std::nullopt;
        // MW: FUTURE - Support signing inputs without the stealth key feature.
        return util::Error{Untranslated("Input does not have the stealth key feature")};
    }

    BlindingFactor input_blind = Pedersen::BlindSwitch(*input.raw_blind, *input.amount);
    input.commitment = Commitment::Blinded(input_blind, *input.amount);

    util::Result<Signature> input_signature_result = InputSignature(
        input.output_id,
        *input.features,
        *input.ephemeral_key,
        *input.spend_key,
        input.extradata
    );
    if (!input_signature_result) {
        return input_signature_result.error();
    }

    input.signature = input_signature_result.value();

    return SignInputResult{input_blind, *input.ephemeral_key, *input.spend_key};
}

struct SignOutputResult {
    BlindingFactor output_blind{};
    SecretKey ephemeral_key{};
    mw::WalletCoin coin{};
};

struct FinalizedPegIn
{
    CAmount amount{};
    mw::Hash kernel_id{};
};

static util::Result<SignOutputResult> SignOutput(MutableOutput& output, const mw::Hash& kernel_id, const SecretKey& rewind_key, const SenderKeyGenerator& generate_sender_key) noexcept
{
    if (output.signature.has_value()) {
        return util::Error{Untranslated("Output is already signed")};
    }

    if (!output.amount || !output.address) {
        return util::Error{Untranslated("Output amount or address missing")};
    }

    BlindingFactor raw_blind;
    util::Result<SecretKey> sender_key_result = generate_sender_key();
    if (!sender_key_result) {
        return sender_key_result.error();
    }

    SecretKey ephemeral_key = sender_key_result.value();
    const std::vector<uint8_t> extra_data = output.message.has_value() ? output.message->extra_data : std::vector<uint8_t>{};
    if (output.message.has_value() &&
        (output.message->features & mw::OutputMessage::EXTRA_DATA_FEATURE_BIT) > 0 &&
        extra_data.empty()) {
        return util::Error{Untranslated("Output extra data missing")};
    }

    mw::Output finalized = mw::Output::Create(
        &raw_blind,
        ephemeral_key,
        rewind_key,
        *output.address,
        *output.amount,
        extra_data
    );

    output.Update(finalized);

    // Populate Coin
    mw::WalletCoin coin;
    coin.blind = raw_blind;
    coin.amount = *output.amount;
    coin.output_id = finalized.GetOutputID();
    coin.sender_key = ephemeral_key;
    coin.address = *output.address;

    BlindingFactor output_blind = Pedersen::BlindSwitch(raw_blind, *output.amount);
    return SignOutputResult{std::move(output_blind), std::move(ephemeral_key), std::move(coin)};
}

static std::optional<util::Error> UpdatePegInScripts(CMutableTransaction& tx) noexcept
{
    std::vector<FinalizedPegIn> pegins;
    pegins.reserve(tx.mweb_tx.kernels.size());

    for (const MutableKernel& kernel : tx.mweb_tx.kernels) {
        if (!kernel.pegin.has_value()) {
            continue;
        }

        const std::optional<mw::Hash> kernel_id = kernel.GetKernelID();
        if (!kernel_id.has_value()) {
            return util::Error{Untranslated("Kernel ID could not be calculated")};
        }

        pegins.push_back(FinalizedPegIn{kernel.pegin.value(), *kernel_id});
    }

    if (pegins.empty()) {
        return std::nullopt;
    }

    std::vector<size_t> pegin_output_indices;
    pegin_output_indices.reserve(tx.vout.size());

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].scriptPubKey.IsMWEBPegin()) {
            pegin_output_indices.push_back(i);
        }
    }

    if (pegin_output_indices.size() != pegins.size()) {
        return util::Error{Untranslated("Peg-in output count does not match MWEB pegin kernel count")};
    }

    // Pair peg-in kernels with canonical peg-in outputs by relative order. This
    // convention survives PSBT round-trips and avoids ambiguous amount-based matching.
    for (size_t i = 0; i < pegins.size(); ++i) {
        CTxOut& out = tx.vout[pegin_output_indices[i]];
        mw::Hash current_kernel_id;
        const bool is_pegin = out.scriptPubKey.IsMWEBPegin(&current_kernel_id);
        assert(is_pegin);

        if (out.nValue != pegins[i].amount) {
            return util::Error{Untranslated("Peg-in output amount does not match MWEB pegin kernel")};
        }

        if (!current_kernel_id.IsZero() && current_kernel_id != pegins[i].kernel_id) {
            return util::Error{Untranslated("Peg-in output kernel ID conflicts with MWEB pegin kernel order")};
        }

        out.scriptPubKey = GetScriptForPegin(pegins[i].kernel_id);
    }

    return std::nullopt;
}

util::Result<mw::SignTxResult> SignTx(CMutableTransaction& tx, const SecretKey& rewind_key, const SenderKeyGenerator& generate_sender_key) noexcept
{
    SignTxResult result{};
    if (tx.mweb_tx.IsNull() || tx.mweb_tx.IsFinal()) {
        return result;
    }

    if (!generate_sender_key) {
        return util::Error{Untranslated("Sender key generator missing")};
    }

    Blinds kernel_offset{};
    Blinds stealth_offset{};

    if (tx.mweb_tx.kernels.empty()) {
        tx.mweb_tx.kernels.push_back(mw::MutableKernel{});
    }

    // Sign kernels
    for (MutableKernel& kernel : tx.mweb_tx.kernels) {
        if (kernel.IsFinal()) {
            continue;
        }

        SecretKey kernel_blind = SecretKey::Random();
        SecretKey stealth_blind = SecretKey::Random();

        mw::Kernel finalized = mw::Kernel::Create(
            kernel_blind,
            stealth_blind,
            kernel.fee,
            kernel.pegin,
            kernel.GetPegOuts(),
            kernel.lock_height,
            kernel.extradata
        );

        kernel.stealth_excess = finalized.GetStealthExcess();
        kernel.excess = finalized.GetExcess();
        kernel.signature = finalized.GetSignature();

        kernel_offset.Sub(kernel_blind);
        stealth_offset.Sub(stealth_blind);
    }

    // Update peg-in scripts with finalized kernel IDs.
    // NOTE: This mutates tx.vout scriptPubKeys and invalidates any previously built
    // PrecomputedTransactionData for this tx.
    const auto error = UpdatePegInScripts(tx);
    if (error) {
        return *error;
    }
    
    std::optional<mw::Hash> first_kernel_id = tx.mweb_tx.kernels.front().GetKernelID();
    if (!first_kernel_id.has_value()) {
        return util::Error{Untranslated("Kernel ID could not be calculated")};
    }

    // Sign outputs
    for (MutableOutput& output : tx.mweb_tx.outputs) {
        if (output.IsFinal()) {
            continue;
        }

        util::Result<SignOutputResult> sign_output_result = SignOutput(output, first_kernel_id.value(), rewind_key, generate_sender_key);
        if (!sign_output_result) {
            return sign_output_result.error();
        }

        const SignOutputResult& signed_output = sign_output_result.value();
        kernel_offset.Add(signed_output.output_blind);
        stealth_offset.Add(signed_output.ephemeral_key);
        result.wallet_coins_by_output_id[*output.CalcOutputID()] = signed_output.coin;
    }

    // Sign inputs
    for (MutableInput& input : tx.mweb_tx.inputs) {
        if (input.IsFinal()) {
            continue;
        }

        util::Result<SignInputResult> input_sign_result = SignInput(input);
        if (!input_sign_result) {
            return input_sign_result.error();
        }

        const SignInputResult& signed_input = input_sign_result.value();
        kernel_offset.Sub(signed_input.input_blind);
        stealth_offset.Add(signed_input.ephemeral_key);
        stealth_offset.Sub(signed_input.spend_key);
    }

    tx.mweb_tx.kernel_offset = kernel_offset.Total();
    tx.mweb_tx.stealth_offset = stealth_offset.Total();

    CTransaction finalized_tx(tx);
    if (finalized_tx.mweb_tx.IsNull()) {
        return util::Error{Untranslated("Failed to construct MWEB transaction")};
    }

    if (const auto tx_error = finalized_tx.mweb_tx.m_transaction->Validate()) {
        return util::Error{Untranslated(strprintf("Validate failed: %s", ConsensusErrorString(*tx_error)))};
    }

    return result;
}

END_NAMESPACE
