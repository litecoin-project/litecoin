// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/wallet/Keychain.h>

#include <key.h>
#include <test_framework/TestMWEB.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

static constexpr uint32_t TEST_ADDRESS_INDEX{10};
static constexpr uint64_t AMOUNT_ZERO{0};
static constexpr uint64_t AMOUNT_ONE{1};
static constexpr uint64_t AMOUNT_LARGE{1'234'567};

SecretKey ScanSecret()
{
    return SecretKey::FromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

SecretKey SpendSecret()
{
    return SecretKey::FromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
}

SecretKey SenderSecret()
{
    return SecretKey::FromHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
}

SecretKey CustomSpendSecret()
{
    return SecretKey::FromHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
}

CKey ToCKey(const SecretKey& secret)
{
    CKey key;
    key.Set(secret.data(), secret.data() + secret.size(), /*fCompressedIn=*/true);
    BOOST_REQUIRE(key.IsValid());
    return key;
}

StealthAddress CustomAddress()
{
    const PublicKey spend_pubkey = PublicKey::From(CustomSpendSecret());
    return StealthAddress(spend_pubkey.Mul(ScanSecret()), spend_pubkey);
}

mw::Output CreateOutput(const StealthAddress& address, const uint64_t amount)
{
    return mw::Output::Create(
        /*blind_out=*/nullptr,
        SenderSecret(),
        ScanSecret(),
        address,
        amount,
        std::vector<uint8_t>{}
    );
}

class TestWalletStorage final : public wallet::WalletStorage
{
public:
    TestWalletStorage()
        : m_database(wallet::CreateDummyWalletDatabase())
    {}

    const std::string GetDisplayName() const override { return "keychain-test"; }
    wallet::WalletDatabase& GetDatabase() const override { return *m_database; }
    bool IsWalletFlagSet(uint64_t) const override { return false; }
    void UnsetBlankWalletFlag(wallet::WalletBatch&) override {}
    bool CanSupportFeature(enum wallet::WalletFeature) const override { return true; }
    bool SetMinVersion(enum wallet::WalletFeature, wallet::WalletBatch* = nullptr) override { return true; }
    const wallet::CKeyingMaterial& GetEncryptionKey() const override { return m_encryption_key; }
    bool HasEncryptionKeys() const override { return false; }
    bool IsLocked() const override { return false; }

private:
    std::unique_ptr<wallet::WalletDatabase> m_database;
    wallet::CKeyingMaterial m_encryption_key;
};

class TestScriptPubKeyMan final : public wallet::ScriptPubKeyMan
{
public:
    explicit TestScriptPubKeyMan(wallet::WalletStorage& storage)
        : wallet::ScriptPubKeyMan(storage)
    {}

    void AddMetadata(const StealthAddress& address, const std::optional<uint32_t>& mweb_index)
    {
        wallet::CKeyMetadata metadata;
        metadata.has_key_origin = mweb_index.has_value();
        metadata.key_origin.hdkeypath.mweb_index = mweb_index;
        m_metadata[address] = std::move(metadata);
    }

    void AddKey(const StealthAddress& address, const SecretKey& secret)
    {
        m_keys[address.GetSpendPubKey().GetID()] = ToCKey(secret);
    }

    bool GetKey(const CKeyID& address, CKey& keyOut) const override
    {
        const auto it = m_keys.find(address);
        if (it == m_keys.end()) {
            return false;
        }

        keyOut = it->second;
        return true;
    }

    std::unique_ptr<wallet::CKeyMetadata> GetMetadata(const CTxDestination& dest) const override
    {
        const auto* address = std::get_if<StealthAddress>(&dest);
        if (!address) {
            return nullptr;
        }

        const auto it = m_metadata.find(*address);
        if (it == m_metadata.end()) {
            return nullptr;
        }

        return std::make_unique<wallet::CKeyMetadata>(it->second);
    }

private:
    std::map<StealthAddress, wallet::CKeyMetadata> m_metadata;
    std::map<CKeyID, CKey> m_keys;
};

struct DerivationVector
{
    uint32_t index;
    const char* scan_pubkey;
    const char* spend_pubkey;
    const char* spend_secret;
};

static constexpr std::array<DerivationVector, 4> DERIVATION_VECTORS{{
    {
        0,
        "03826d3f8e180da6ab4dcd512f06670c2aa018b134953312de8095433f5da4bd91",
        "02a5ca62e733cf7bd9c2592ecc793970c4090a191cbc5cc34bef3a0a6793d3e236",
        "dd2e9d1894e5782f5b00ad726b098a31985ddf35c97e4149ab1c4f9f3e2b943a",
    },
    {
        1,
        "0203386c706772e81f58b8da550f6433fe35e6553cb2e7c041997da9592f84dabd",
        "0307855c0a8ae877bf9de8583928f857322e91727a4639bc96c2956e490444133d",
        "5d71b3b569974352e724620c02e8202550bd5725b3635c0ab6207ca4754ea7d0",
    },
    {
        10,
        "0398ced716ba3e1d3d9b983783fe675243d4f878ec4bc6bc50e0a307f33d6e943b",
        "039412686710c264fc11881d45100eb50a1dbd9e987d1fd67a7d83c45fa8dd8bd7",
        "cbfd1b1e8969e4df915fa3702547c6f5f15f4d3717344d9774465a5cff8a434b",
    },
    {
        42,
        "03f78aabcf1759cbec37dd395fad62f2c92d1fb8578dc2e8397bd31aa38e6efa91",
        "02193b11a4716bc4646e6dbe25287d483dd10cbb1ac883363ae581abb810e57d01",
        "86cdef719db3a2900ed66df3ef14b3bc4f7df62f034ef4975eb51dbd30b84353",
    },
}};

void CheckRewoundCoin(
    const mw::WalletCoin& coin,
    const mw::Output& output,
    const uint32_t address_index,
    const uint64_t amount,
    const StealthAddress& address)
{
    BOOST_CHECK_EQUAL(coin.address_index, address_index);
    BOOST_CHECK_EQUAL(coin.amount, static_cast<CAmount>(amount));
    BOOST_CHECK(coin.output_id == output.GetOutputID());
    BOOST_REQUIRE(coin.address.has_value());
    BOOST_CHECK(*coin.address == address);
    BOOST_CHECK(coin.blind.has_value());
    BOOST_CHECK(coin.shared_secret.has_value());
    BOOST_REQUIRE(coin.master_scan_key_id.has_value());
    BOOST_CHECK(*coin.master_scan_key_id == PublicKey::From(ScanSecret()).GetID());
}

void CheckNotRewound(const mw::Keychain& keychain, const mw::Output& output)
{
    mw::WalletCoin coin;
    coin.Reset();
    mw::WalletCoin unchanged;
    unchanged.Reset();

    BOOST_CHECK(!keychain.RewindOutput(output, coin));
    BOOST_CHECK(coin == unchanged);
}

mw::Output WithStandardFields(const mw::Output& output, mw::OutputStandardFields standard_fields)
{
    return mw::Output(
        output.GetCommitment(),
        output.GetSenderPubKey(),
        output.GetReceiverPubKey(),
        mw::OutputMessage(mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT, std::move(standard_fields)),
        output.GetRangeProof(),
        output.GetSignature()
    );
}

mw::Output WithoutStandardFields(const mw::Output& output)
{
    return mw::Output(
        output.GetCommitment(),
        output.GetSenderPubKey(),
        output.GetReceiverPubKey(),
        mw::OutputMessage(0, std::optional<mw::OutputStandardFields>{std::nullopt}, std::vector<uint8_t>{}),
        output.GetRangeProof(),
        output.GetSignature()
    );
}

PublicKey MalformedPublicKey(const uint8_t prefix, const uint8_t fill)
{
    std::array<uint8_t, 33> bytes;
    bytes.fill(fill);
    bytes[0] = prefix;
    return PublicKey(bytes.data());
}

mw::Output WithReceiverPublicKey(const mw::Output& output, PublicKey receiver_pubkey)
{
    return mw::Output(
        output.GetCommitment(),
        output.GetSenderPubKey(),
        std::move(receiver_pubkey),
        output.GetOutputMessage(),
        output.GetRangeProof(),
        output.GetSignature());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(TestKeychain, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(DeterministicDerivations)
{
    mw::Keychain keychain(nullptr, ScanSecret(), SpendSecret());

    BOOST_CHECK(keychain.HasSpendPubKey());
    BOOST_CHECK(keychain.HasSpendSecret());

    const SecretKey rewind_key = mw::DeriveRewindKey(ScanSecret());
    const SecretKey sender_key_0 = mw::DeriveSenderSigningKey(ScanSecret(), 0);
    const SecretKey sender_key_1 = mw::DeriveSenderSigningKey(ScanSecret(), 1);

    BOOST_CHECK_EQUAL(rewind_key.ToHex(), "ba520343da9cebd5b8b2acce4f5bb4e3d232d35156411ba4853f583ed39e873b");
    BOOST_CHECK_EQUAL(sender_key_0.ToHex(), "287de0d46e27a3b2d7c2549a3711dd826d397096254838a01495735637a5dfd5");
    BOOST_CHECK_EQUAL(sender_key_1.ToHex(), "b26baf37f7baeaa90c28d802d589bb3669b39bbccd80d3ec55be688397be4f4c");
    BOOST_CHECK(sender_key_0 != sender_key_1);
    BOOST_CHECK(keychain.GetRewindKey() == rewind_key);
    BOOST_CHECK(keychain.GetSenderSigningKey(0) == sender_key_0);
    BOOST_CHECK(keychain.GetSenderSigningKey(1) == sender_key_1);

    for (const DerivationVector& vector : DERIVATION_VECTORS) {
        const StealthAddress address = mw::DeriveSubaddress(PublicKey::From(SpendSecret()), ScanSecret(), vector.index);
        const SecretKey subaddress_spend_key = mw::DeriveSubaddressSpendKey(SpendSecret(), ScanSecret(), vector.index);

        BOOST_CHECK_EQUAL(address.A().ToHex(), vector.scan_pubkey);
        BOOST_CHECK_EQUAL(address.B().ToHex(), vector.spend_pubkey);
        BOOST_CHECK_EQUAL(subaddress_spend_key.ToHex(), vector.spend_secret);
        BOOST_CHECK(PublicKey::From(subaddress_spend_key) == address.B());
        BOOST_CHECK(address.A() == address.B().Mul(ScanSecret()));
        BOOST_CHECK(keychain.DeriveAddress(vector.index) == address);
        BOOST_CHECK(keychain.GetSubaddressSpendKey(vector.index) == subaddress_spend_key);
    }

    const StealthAddress address_10 = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    const SecretKey spend_key_10 = keychain.GetSubaddressSpendKey(TEST_ADDRESS_INDEX);
    keychain.Lock();
    BOOST_CHECK(keychain.HasSpendPubKey());
    BOOST_CHECK(!keychain.HasSpendSecret());
    BOOST_CHECK(keychain.DeriveAddress(TEST_ADDRESS_INDEX) == address_10);

    keychain.Unlock(SpendSecret());
    BOOST_CHECK(keychain.HasSpendSecret());
    BOOST_CHECK(keychain.GetSubaddressSpendKey(TEST_ADDRESS_INDEX) == spend_key_10);
}

BOOST_AUTO_TEST_CASE(LookupAddressIndex)
{
    TestWalletStorage storage;
    TestScriptPubKeyMan spk_man(storage);
    mw::Keychain keychain(&spk_man, ScanSecret(), SpendSecret());

    const StealthAddress indexed_address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    spk_man.AddMetadata(indexed_address, TEST_ADDRESS_INDEX);
    const std::optional<uint32_t> indexed_result = keychain.LookupAddressIndex(indexed_address);
    BOOST_REQUIRE(indexed_result.has_value());
    BOOST_CHECK_EQUAL(indexed_result.value(), TEST_ADDRESS_INDEX);

    const StealthAddress custom_address = keychain.DeriveAddress(42);
    spk_man.AddMetadata(custom_address, std::nullopt);
    const std::optional<uint32_t> custom_result = keychain.LookupAddressIndex(custom_address);
    BOOST_REQUIRE(custom_result.has_value());
    BOOST_CHECK_EQUAL(custom_result.value(), mw::CUSTOM_KEY);

    BOOST_CHECK(!keychain.LookupAddressIndex(keychain.DeriveAddress(1)).has_value());
}

BOOST_AUTO_TEST_CASE(RewindOutput_OwnedKeychainOutputs)
{
    TestWalletStorage storage;
    TestScriptPubKeyMan spk_man(storage);
    mw::Keychain full_keychain(&spk_man, ScanSecret(), SpendSecret());

    const StealthAddress address = full_keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    spk_man.AddMetadata(address, TEST_ADDRESS_INDEX);

    for (const uint64_t amount : {AMOUNT_ZERO, AMOUNT_ONE, AMOUNT_LARGE}) {
        const mw::Output output = CreateOutput(address, amount);
        mw::WalletCoin coin;
        coin.Reset();
        BOOST_REQUIRE(full_keychain.RewindOutput(output, coin));
        CheckRewoundCoin(coin, output, TEST_ADDRESS_INDEX, amount, address);
        const std::optional<SecretKey> spend_key = full_keychain.CalculateOutputSpendKey(coin);
        BOOST_REQUIRE(spend_key);
        BOOST_CHECK(PublicKey::From(*spend_key) == output.GetReceiverPubKey());
    }

    const mw::Output output = CreateOutput(address, AMOUNT_LARGE);
    mw::Keychain spend_pubkey_only(&spk_man, ScanSecret(), PublicKey::From(SpendSecret()));
    mw::WalletCoin watch_only_coin;
    watch_only_coin.Reset();
    BOOST_REQUIRE(spend_pubkey_only.RewindOutput(output, watch_only_coin));
    CheckRewoundCoin(watch_only_coin, output, TEST_ADDRESS_INDEX, AMOUNT_LARGE, address);
    BOOST_CHECK(!spend_pubkey_only.CalculateOutputSpendKey(watch_only_coin));

    mw::Keychain scan_only(&spk_man, ScanSecret(), std::optional<PublicKey>{std::nullopt});
    mw::WalletCoin scan_only_coin;
    scan_only_coin.Reset();
    BOOST_REQUIRE(scan_only.RewindOutput(output, scan_only_coin));
    CheckRewoundCoin(scan_only_coin, output, TEST_ADDRESS_INDEX, AMOUNT_LARGE, address);
    BOOST_CHECK(!scan_only.CalculateOutputSpendKey(scan_only_coin));
}

BOOST_AUTO_TEST_CASE(RewindOutput_CustomKeyOutputs)
{
    const StealthAddress custom_address = CustomAddress();
    const mw::Output output = CreateOutput(custom_address, AMOUNT_ONE);

    {
        TestWalletStorage storage;
        TestScriptPubKeyMan spk_man(storage);
        spk_man.AddMetadata(custom_address, std::nullopt);

        mw::Keychain keychain(&spk_man, ScanSecret(), std::optional<PublicKey>{std::nullopt});
        mw::WalletCoin coin;
        coin.Reset();
        BOOST_REQUIRE(keychain.RewindOutput(output, coin));
        CheckRewoundCoin(coin, output, mw::CUSTOM_KEY, AMOUNT_ONE, custom_address);
        BOOST_CHECK(!keychain.CalculateOutputSpendKey(coin));
    }

    {
        TestWalletStorage storage;
        TestScriptPubKeyMan spk_man(storage);
        spk_man.AddMetadata(custom_address, std::nullopt);
        spk_man.AddKey(custom_address, CustomSpendSecret());

        mw::Keychain keychain(&spk_man, ScanSecret(), std::optional<PublicKey>{std::nullopt});
        mw::WalletCoin coin;
        coin.Reset();
        BOOST_REQUIRE(keychain.RewindOutput(output, coin));
        CheckRewoundCoin(coin, output, mw::CUSTOM_KEY, AMOUNT_ONE, custom_address);
        const std::optional<SecretKey> spend_key = keychain.CalculateOutputSpendKey(coin);
        BOOST_REQUIRE(spend_key);
        BOOST_CHECK(PublicKey::From(*spend_key) == output.GetReceiverPubKey());
    }
}

BOOST_AUTO_TEST_CASE(WalletCoinLegacySpendKeysAreDiscarded)
{
    const uint32_t address_index{TEST_ADDRESS_INDEX};
    const std::optional<SecretKey> spend_key{SpendSecret()};
    const std::optional<BlindingFactor> blind{BlindingFactor::Random()};
    const CAmount amount{12345};
    const mw::Hash output_id{mw::Hash::ValueOf(42)};
    const std::optional<SecretKey> sender_key{SenderSecret()};
    const std::optional<StealthAddress> address{mw::DeriveSubaddress(PublicKey::From(SpendSecret()), ScanSecret(), address_index)};
    const std::optional<SecretKey> shared_secret{SecretKey::Random()};
    const std::optional<CKeyID> master_scan_key_id{PublicKey::From(ScanSecret()).GetID()};

    for (uint8_t version{0}; version <= 3; ++version) {
        CDataStream legacy(SER_DISK, PROTOCOL_VERSION);
        legacy << version << VARINT(address_index) << spend_key << blind
               << VARINT_MODE(amount, VarIntMode::NONNEGATIVE_SIGNED) << output_id;
        if (version >= 1) {
            legacy << sender_key << address;
        }
        if (version >= 2) {
            legacy << shared_secret;
        }
        if (version >= 3) {
            legacy << master_scan_key_id;
        }

        std::vector<uint8_t> legacy_bytes(legacy.size());
        std::transform(legacy.begin(), legacy.end(), legacy_bytes.begin(), [](std::byte value) {
            return std::to_integer<uint8_t>(value);
        });
        const mw::WalletCoin migrated = mw::WalletCoin::Deserialize(legacy_bytes);
        BOOST_CHECK(migrated.NeedsPersistenceUpgrade());
        BOOST_CHECK(migrated.HadPersistedSpendKey());
        BOOST_CHECK_EQUAL(migrated.address_index, address_index);
        BOOST_CHECK(migrated.output_id == output_id);

        const std::vector<uint8_t> upgraded_bytes = migrated.Serialized();
        BOOST_REQUIRE(!upgraded_bytes.empty());
        BOOST_CHECK_EQUAL(upgraded_bytes.front(), mw::WalletCoin::LATEST_VERSION);
        BOOST_CHECK(std::search(upgraded_bytes.begin(), upgraded_bytes.end(), spend_key->vec().begin(), spend_key->vec().end()) == upgraded_bytes.end());

        const mw::WalletCoin upgraded = mw::WalletCoin::Deserialize(upgraded_bytes);
        BOOST_CHECK(!upgraded.NeedsPersistenceUpgrade());
        BOOST_CHECK(!upgraded.HadPersistedSpendKey());
        BOOST_CHECK(upgraded == migrated);
    }
}

BOOST_AUTO_TEST_CASE(RewindOutput_Rejections)
{
    TestWalletStorage storage;
    TestScriptPubKeyMan spk_man(storage);
    mw::Keychain keychain(&spk_man, ScanSecret(), SpendSecret());

    const StealthAddress address = keychain.DeriveAddress(TEST_ADDRESS_INDEX);
    spk_man.AddMetadata(address, TEST_ADDRESS_INDEX);
    const mw::Output output = CreateOutput(address, AMOUNT_LARGE);

    mw::Keychain wrong_scan_keychain(&spk_man, SenderSecret(), SpendSecret());
    CheckNotRewound(wrong_scan_keychain, output);

    CheckNotRewound(keychain, WithoutStandardFields(output));

    CheckNotRewound(
        keychain,
        WithStandardFields(
            output,
            mw::OutputStandardFields(
                MalformedPublicKey(0x04, 0x00),
                output.GetViewTag(),
                output.GetMaskedValue(),
                output.GetMaskedNonce())
        )
    );

    CheckNotRewound(keychain, WithReceiverPublicKey(output, MalformedPublicKey(0x02, 0xff)));

    TestWalletStorage unknown_storage;
    TestScriptPubKeyMan unknown_spk_man(unknown_storage);
    mw::Keychain unknown_keychain(&unknown_spk_man, ScanSecret(), SpendSecret());
    CheckNotRewound(unknown_keychain, output);

    CheckNotRewound(
        keychain,
        WithStandardFields(
            output,
            mw::OutputStandardFields(output.Ke(), output.GetViewTag() ^ 0x01, output.GetMaskedValue(), output.GetMaskedNonce())
        )
    );

    CheckNotRewound(
        keychain,
        WithStandardFields(
            output,
            mw::OutputStandardFields(output.Ke(), output.GetViewTag(), output.GetMaskedValue() ^ 0x01, output.GetMaskedNonce())
        )
    );

    BigInt<16> tampered_nonce = output.GetMaskedNonce();
    tampered_nonce[0] ^= 0x01;
    CheckNotRewound(
        keychain,
        WithStandardFields(
            output,
            mw::OutputStandardFields(output.Ke(), output.GetViewTag(), output.GetMaskedValue(), tampered_nonce)
        )
    );
}

BOOST_AUTO_TEST_SUITE_END()
