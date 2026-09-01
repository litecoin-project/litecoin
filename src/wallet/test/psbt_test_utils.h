// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TEST_PSBT_TEST_UTILS_H
#define BITCOIN_WALLET_TEST_PSBT_TEST_UTILS_H

#include <key.h>
#include <key_io.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <script/standard.h>
#include <util/strencodings.h>
#include <wallet/mweb_psbt.h>

#include <map>
#include <optional>
#include <string>

namespace wallet {
namespace test {

//! Deterministic secret from a repeated hex character (e.g. '1'..'9', 'a'..'f').
inline SecretKey TestSecret(char hex_char)
{
    return SecretKey::FromHex(std::string(64, hex_char));
}

//! In-memory MWEBSigningKeyStore with no wallet behind it.
class MockMWEBKeyStore final : public MWEBSigningKeyStore
{
public:
    std::map<mw::Hash, mw::WalletCoin> m_coins;
    std::map<CKeyID, mw::Keychain::Ptr> m_keychains;
    mw::Keychain::Ptr m_active_keychain;
    std::optional<std::string> m_inferred_descriptor;

    std::optional<mw::WalletCoin> GetWalletCoin(const mw::Hash& output_id) const override
    {
        const auto it = m_coins.find(output_id);
        if (it == m_coins.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    mw::Keychain::Ptr GetActiveKeychain() const override
    {
        return m_active_keychain;
    }

    mw::Keychain::Ptr GetKeychain(const CKeyID& master_scan_key_id) const override
    {
        const auto it = m_keychains.find(master_scan_key_id);
        return it == m_keychains.end() ? nullptr : it->second;
    }

    std::optional<std::string> InferAddressDescriptor(const mw::WalletCoin&) const override
    {
        return m_inferred_descriptor;
    }
};

//! Deterministic MWEB master keypair with subaddress and descriptor derivation
//! matching MWEBDescriptor (script/descriptor.cpp).
struct MWEBTestKeys
{
    SecretKey scan_secret;
    SecretKey master_spend_secret;

    static MWEBTestKeys Create(char scan_hex_char = '1', char spend_hex_char = '2')
    {
        return MWEBTestKeys{TestSecret(scan_hex_char), TestSecret(spend_hex_char)};
    }

    //! b_i = b + HASH(ADDRESS, i || a)
    SecretKey SubaddressSpendSecret(uint32_t index) const
    {
        return mw::DeriveSubaddressSpendKey(master_spend_secret, scan_secret, index);
    }

    //! (A_i, B_i) where B_i = b_i*G and A_i = a*B_i
    StealthAddress Address(uint32_t index) const
    {
        return mw::DeriveSubaddress(PublicKey::From(master_spend_secret), scan_secret, index);
    }

    //! Single-index mweb() descriptor carrying both private keys.
    std::string Descriptor(uint32_t index) const
    {
        return strprintf("mweb(%s,%s,%u)", EncodeSecret(ToCKey(scan_secret)), EncodeSecret(ToCKey(master_spend_secret)), index);
    }

    //! The pubkey a receiver's output_pubkey is derived from for a given shared secret.
    PublicKey OutputPubKey(uint32_t index, const SecretKey& shared_secret) const
    {
        return mw::DeriveOutputPubKey(Address(index), shared_secret);
    }

    static CKey ToCKey(const SecretKey& secret)
    {
        CKey key;
        key.Set(secret.vec().begin(), secret.vec().end(), /*fCompressedIn=*/true);
        // Repeated-'f' secrets (0xff...f) exceed the secp256k1 group order.
        assert(key.IsValid());
        return key;
    }
};

//! Sender key generator drawing random keys, as wallets without a
//! deterministic sender-key cache do.
inline mw::SenderKeyGenerator TestSenderKeyGenerator()
{
    return []() -> util::Result<SecretKey> { return SecretKey::Random(); };
}

//! An MWEB-to-MWEB transaction: one input (100k), one output (90k), fee kernel (10k).
//! The input's spend key is left to the caller via the spend_keys map.
inline PartiallySignedTransaction SignableMWEBPSBT(const mw::Hash& input_output_id, const SecretKey& input_shared_secret, const StealthAddress& recipient)
{
    CMutableTransaction mtx;

    mw::MutableInput input(input_output_id);
    input.amount = 100'000;
    mtx.mweb_tx.inputs.push_back(std::move(input));

    mw::MutableOutput output;
    output.amount = 90'000;
    output.address = recipient;
    mtx.mweb_tx.outputs.push_back(std::move(output));

    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    PartiallySignedTransaction psbt(mtx, 2);
    // SetupFromTx does not carry the shared secret; the Updater stage normally fills it.
    psbt.inputs.back().mweb_shared_secret = input_shared_secret;
    return psbt;
}

//! A peg-in transaction: canonical peg-in output (100k, placeholder script),
//! one MWEB output (90k), peg-in kernel (pegin 100k, fee 10k). No MWEB inputs.
inline CMutableTransaction PeginTx(const StealthAddress& recipient, CAmount pegin_vout_amount = 100'000)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(pegin_vout_amount, GetScriptForPegin(mw::Hash{}));

    mw::MutableOutput output;
    output.amount = 90'000;
    output.address = recipient;
    mtx.mweb_tx.outputs.push_back(std::move(output));

    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    kernel.pegin = 100'000;
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    return mtx;
}

} // namespace test
} // namespace wallet

#endif // BITCOIN_WALLET_TEST_PSBT_TEST_UTILS_H
