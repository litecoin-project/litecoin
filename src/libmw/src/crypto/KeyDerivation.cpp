#include <mw/crypto/KeyDerivation.h>

#include <mw/crypto/Hasher.h>
#include <mw/crypto/SecretKeys.h>

MW_NAMESPACE

//
// Forward derivations
//

SecretKey DeriveSubaddressSpendKey(const SecretKey& master_spend_secret, const SecretKey& master_scan_secret, const uint32_t index)
{
    const SecretKey subaddress_offset = SecretKey::FromHash(Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(master_scan_secret)
        .hash());

    return SecretKeys::From(master_spend_secret).Add(subaddress_offset).Total();
}

StealthAddress DeriveSubaddress(const PublicKey& master_spend_pubkey, const SecretKey& master_scan_secret, const uint32_t index)
{
    const SecretKey subaddress_offset = SecretKey::FromHash(Hasher(EHashTag::ADDRESS)
        .Append<uint32_t>(index)
        .Append(master_scan_secret)
        .hash());
    const PublicKey subaddress_spend_pubkey = master_spend_pubkey.Add(subaddress_offset);
    return StealthAddress(subaddress_spend_pubkey.Mul(master_scan_secret), subaddress_spend_pubkey);
}

BigInt<16> DeriveOutputNonce(const SecretKey& sender_key)
{
    return BigInt<16>(Hashed(EHashTag::NONCE, sender_key).data());
}

SecretKey DeriveOutputSendKey(const StealthAddress& receiver_address, const uint64_t amount, const BigInt<16>& nonce)
{
    return SecretKey::FromHash(Hasher(EHashTag::SEND_KEY)
        .Append(receiver_address.A())
        .Append(receiver_address.B())
        .Append(amount)
        .Append(nonce)
        .hash());
}

SecretKey DeriveSharedSecret(const SecretKey& sender_key, const StealthAddress& receiver_address, const uint64_t amount)
{
    const BigInt<16> nonce = DeriveOutputNonce(sender_key);
    const SecretKey send_key = DeriveOutputSendKey(receiver_address, amount, nonce);
    return SecretKey::FromHash(Hashed(EHashTag::DERIVE, receiver_address.A().Mul(send_key)));
}

PublicKey DeriveOutputKeyExchangePubKey(const StealthAddress& receiver_address, const SecretKey& output_send_key)
{
    return receiver_address.B().Mul(output_send_key);
}

PublicKey DeriveOutputPubKey(const StealthAddress& receiver_address, const SecretKey& shared_secret)
{
    return receiver_address.B().Mul(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, shared_secret)));
}

SecretKey DeriveOutputSpendKey(const SecretKey& subaddress_spend_key, const SecretKey& shared_secret)
{
    return SecretKeys::From(subaddress_spend_key)
        .Mul(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, shared_secret)))
        .Total();
}

BlindingFactor DeriveOutputRawBlind(const SecretKey& shared_secret)
{
    return SecretKey::FromHash(Hashed(EHashTag::BLIND, shared_secret));
}

SecretKey DeriveRewindKey(const SecretKey& master_scan_secret)
{
    return SecretKey::FromHash(Hashed(EHashTag::REWIND_KEY, master_scan_secret));
}

SecretKey DeriveSenderSigningKey(const SecretKey& master_scan_secret, const uint64_t index)
{
    const SecretKey sender_root = SecretKey::FromHash(Hashed(EHashTag::SENDER_ROOT, master_scan_secret));
    const SecretKey sender_key = SecretKey::FromHash(Hasher(EHashTag::SENDER_ROOT)
        .Append(sender_root)
        .Append(index)
        .hash());
    return SecretKeys::From(sender_key).Total();
}

//
// Recovery from published outputs
//

uint8_t RecoverViewTag(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret)
{
    return Hashed(EHashTag::TAG, key_exchange_pubkey.Mul(master_scan_secret))[0];
}

SecretKey RecoverSharedSecret(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret)
{
    return SecretKey::FromHash(Hashed(EHashTag::DERIVE, key_exchange_pubkey.Mul(master_scan_secret)));
}

PublicKey RecoverSubaddressSpendPubKey(const PublicKey& output_pubkey, const SecretKey& shared_secret)
{
    return output_pubkey.Div(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, shared_secret)));
}

StealthAddress RecoverSubaddress(const PublicKey& output_pubkey, const SecretKey& shared_secret, const SecretKey& master_scan_secret)
{
    const PublicKey subaddress_spend_pubkey = RecoverSubaddressSpendPubKey(output_pubkey, shared_secret);
    return StealthAddress(subaddress_spend_pubkey.Mul(master_scan_secret), subaddress_spend_pubkey);
}

END_NAMESPACE
