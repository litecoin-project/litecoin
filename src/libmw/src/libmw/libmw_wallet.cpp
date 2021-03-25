#include <libmw/wallet.h>

#include "Transformers.h"

#include <mw/models/tx/Transaction.h>
#include <mw/wallet/Keychain.h>
#include <mw/wallet/Transact.h>
#include <mw/wallet/Wallet.h>

LIBMW_NAMESPACE

MWEXPORT libmw::MWEBAddress KeychainRef::GetAddress(const uint32_t index)
{
    assert(pKeychain != nullptr);

    return TransformAddress(pKeychain->GetStealthAddress(index));
}

WALLET_NAMESPACE

MWEXPORT libmw::KeychainRef LoadKeychain(
    const libmw::PrivateKey& scan_key,
    const libmw::PrivateKey& spend_key,
    const uint32_t address_index_counter)
{
    auto pKeychain = std::make_shared<mw::Keychain>(
        scan_key,
        spend_key,
        address_index_counter
    );
    return libmw::KeychainRef{ pKeychain };
}

MWEXPORT libmw::TxRef CreateTx(
    const std::vector<libmw::Coin>& input_coins,
    const std::vector<libmw::Recipient>& recipients,
    const boost::optional<uint64_t>& pegin_amount,
    const uint64_t fee)
{
    std::vector<std::pair<uint64_t, StealthAddress>> receivers;
    std::vector<PegOutCoin> pegouts;

    for (const libmw::Recipient& recipient : recipients) {
        if (recipient.which() == 0) {
            const libmw::MWEBRecipient& mweb_recipient = boost::get<libmw::MWEBRecipient>(recipient);
            receivers.push_back(std::make_pair(mweb_recipient.amount, TransformAddress(mweb_recipient.address)));
        } else if (recipient.which() == 1) {
            const libmw::PegInRecipient& pegin_recipient = boost::get<libmw::PegInRecipient>(recipient);
            receivers.push_back(std::make_pair(pegin_recipient.amount, TransformAddress(pegin_recipient.address)));
        } else {
            const libmw::PegOutRecipient& pegout_recipient = boost::get<libmw::PegOutRecipient>(recipient);
            pegouts.push_back(PegOutCoin(pegout_recipient.amount, pegout_recipient.scriptPubKey));
        }
    }

    mw::Transaction::CPtr pTransaction = Transact::CreateTx(input_coins, receivers, pegouts, pegin_amount, fee);
    return libmw::TxRef{ pTransaction };
}

MWEXPORT bool RewindBlockOutput(
    const libmw::KeychainRef& keychain,
    const libmw::BlockRef& block,
    const libmw::Commitment& output_commit,
    libmw::Coin& coin_out)
{
    assert(keychain.pKeychain != nullptr);
    assert(block.pBlock != nullptr);

    Wallet wallet(keychain.pKeychain);
    ::Commitment commitment(output_commit);

    for (const Output& output : block.pBlock->GetOutputs()) {
        if (output.GetCommitment() == commitment) {
            return wallet.RewindOutput(output, coin_out);
        }
    }

    return false;
}

MWEXPORT bool RewindTxOutput(
    const libmw::KeychainRef& keychain,
    const libmw::TxRef& tx,
    const libmw::Commitment& output_commit,
    libmw::Coin& coin_out)
{
    assert(keychain.pKeychain != nullptr);
    assert(tx.pTransaction!= nullptr);

    Wallet wallet(keychain.pKeychain);
    ::Commitment commitment(output_commit);

    for (const Output& output : tx.pTransaction->GetOutputs()) {
        if (output.GetCommitment() == commitment) {
            return wallet.RewindOutput(output, coin_out);
        }
    }

    return false;
}

END_NAMESPACE // wallet
END_NAMESPACE // libmw