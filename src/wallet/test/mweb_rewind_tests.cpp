// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <mweb/mweb_wallet.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/WalletCoin.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <utility>
#include <vector>

namespace wallet {
namespace {

class MWEBRewindTestingSetup : public TestChain100Setup
{
public:
    struct SentOutput {
        mw::Output output;
        mw::WalletCoin staged_coin;
        SecretKey sender_key;
        BlindingFactor blind;
    };

    CWallet m_wallet;

    MWEBRewindTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        BOOST_REQUIRE(m_wallet.LoadWallet() == DBErrors::LOAD_OK);
        SetupFreshWallet(m_wallet);
    }

    void SetupFreshWallet(CWallet& wallet)
    {
        wallet.SetupLegacyScriptPubKeyMan();
        WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_MWEB));

        LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
        BOOST_REQUIRE(spk_man);
        LOCK(spk_man->cs_KeyStore);
        spk_man->SetHDSeed(spk_man->GenerateNewSeed());
    }

    mw::Keychain::Ptr Keychain(CWallet& wallet) const
    {
        ScriptPubKeyMan* spk_man = wallet.GetScriptPubKeyMan(OutputType::MWEB, false);
        BOOST_REQUIRE(spk_man);
        const mw::Keychain::Ptr keychain = spk_man->GetMWEBKeychain();
        BOOST_REQUIRE(keychain);
        return keychain;
    }

    StealthAddress NewMWEBAddress(CWallet& wallet) const
    {
        const util::Result<CTxDestination> destination = wallet.GetNewDestination(OutputType::MWEB, "");
        BOOST_REQUIRE(destination);
        BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*destination));
        return std::get<StealthAddress>(*destination);
    }

    mw::Output IncomingOutput(const StealthAddress& address, CAmount amount) const
    {
        return mw::Output::Create(
            /*blind_out=*/nullptr,
            SecretKey::Random(),
            SecretKey::Random(),
            address,
            amount,
            /*extra_data=*/{});
    }

    SentOutput CreateSentOutput(CWallet& wallet, const StealthAddress& address, CAmount amount, uint64_t sender_index) const
    {
        const mw::Keychain::Ptr keychain = Keychain(wallet);
        const SecretKey sender_key = keychain->GetSenderSigningKey(sender_index);
        BlindingFactor blind;
        mw::Output output = mw::Output::Create(
            &blind,
            sender_key,
            keychain->GetRewindKey(),
            address,
            amount,
            /*extra_data=*/{});

        mw::WalletCoin staged_coin;
        staged_coin.blind = blind;
        staged_coin.amount = amount;
        staged_coin.output_id = output.GetOutputID();
        staged_coin.sender_key = sender_key;
        staged_coin.address = address;
        return {std::move(output), std::move(staged_coin), sender_key, blind};
    }

    bool Rewind(CWallet& wallet, const mw::Output& output) const
    {
        LOCK(wallet.cs_wallet);
        return wallet.GetMWWallet()->RewindOutput(output);
    }

    mw::WalletCoin GetCoin(CWallet& wallet, const mw::Hash& output_id) const
    {
        LOCK(wallet.cs_wallet);
        mw::WalletCoin coin;
        BOOST_REQUIRE(wallet.GetMWEBWalletCoin(output_id, coin));
        return coin;
    }

    bool HasCoin(CWallet& wallet, const mw::Hash& output_id) const
    {
        LOCK(wallet.cs_wallet);
        mw::WalletCoin coin;
        return wallet.GetMWEBWalletCoin(output_id, coin);
    }

    mw::WalletCoin ReadPersistedCoin(CWallet& wallet, const mw::Hash& output_id) const
    {
        mw::WalletCoin coin;
        BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::COIN, output_id), coin));
        return coin;
    }

    void CheckOwnedMetadata(
        CWallet& wallet,
        const mw::WalletCoin& coin,
        const mw::Output& output,
        const StealthAddress& address,
        CAmount amount,
        uint32_t address_index) const
    {
        BOOST_CHECK(coin.IsMine());
        BOOST_CHECK_EQUAL(coin.address_index, address_index);
        BOOST_CHECK_EQUAL(coin.amount, amount);
        BOOST_CHECK(coin.output_id == output.GetOutputID());
        BOOST_REQUIRE(coin.address);
        BOOST_CHECK(*coin.address == address);
        BOOST_REQUIRE(coin.blind);
        BOOST_REQUIRE(coin.shared_secret);
        BOOST_REQUIRE(coin.master_scan_key_id);
        BOOST_CHECK(*coin.master_scan_key_id == PublicKey::From(Keychain(wallet)->GetScanSecret()).GetID());

        const std::optional<SecretKey> spend_key = Keychain(wallet)->CalculateOutputSpendKey(coin);
        BOOST_REQUIRE(spend_key);
        BOOST_CHECK(PublicKey::From(*spend_key) == output.GetReceiverPubKey());
    }

};

BOOST_FIXTURE_TEST_SUITE(mweb_rewind_tests, MWEBRewindTestingSetup)

// Rewind discovers wallet outputs, records wallet-sent outputs, and ignores unrelated outputs.
BOOST_AUTO_TEST_CASE(RewindClassifiesOwnedSentAndUnrelatedOutputs)
{
    static constexpr CAmount OWNED_AMOUNT{1'100'000};
    static constexpr CAmount SENT_AMOUNT{2'200'000};
    static constexpr CAmount UNRELATED_AMOUNT{3'300'000};
    const StealthAddress owned_address = NewMWEBAddress(m_wallet);
    const StealthAddress external_address = StealthAddress::Random();
    const mw::Output owned = IncomingOutput(owned_address, OWNED_AMOUNT);
    const SentOutput sent = CreateSentOutput(m_wallet, external_address, SENT_AMOUNT, /*sender_index=*/0);
    const mw::Output unrelated = IncomingOutput(StealthAddress::Random(), UNRELATED_AMOUNT);

    BOOST_CHECK(Rewind(m_wallet, owned));
    BOOST_CHECK(!Rewind(m_wallet, sent.output));
    BOOST_CHECK(!Rewind(m_wallet, unrelated));

    const std::optional<uint32_t> owned_index = Keychain(m_wallet)->LookupAddressIndex(owned_address);
    BOOST_REQUIRE(owned_index);
    CheckOwnedMetadata(m_wallet, GetCoin(m_wallet, owned.GetOutputID()), owned, owned_address, OWNED_AMOUNT, *owned_index);

    const mw::WalletCoin sent_coin = GetCoin(m_wallet, sent.output.GetOutputID());
    BOOST_CHECK(!sent_coin.IsMine());
    BOOST_CHECK_EQUAL(sent_coin.amount, SENT_AMOUNT);
    BOOST_REQUIRE(sent_coin.sender_key);
    BOOST_CHECK(*sent_coin.sender_key == sent.sender_key);
    BOOST_REQUIRE(sent_coin.blind);
    BOOST_REQUIRE(sent_coin.shared_secret);
    BOOST_CHECK(!sent_coin.address);

    BOOST_CHECK(!HasCoin(m_wallet, unrelated.GetOutputID()));
}

// Complete owned metadata is durable and remains unchanged when the same output is scanned again.
BOOST_AUTO_TEST_CASE(OwnedOutputMetadataPersistsAndRewindsIdempotently)
{
    static constexpr CAmount AMOUNT{4'400'000};
    const StealthAddress address = NewMWEBAddress(m_wallet);
    const mw::Output output = IncomingOutput(address, AMOUNT);
    const std::optional<uint32_t> address_index = Keychain(m_wallet)->LookupAddressIndex(address);
    BOOST_REQUIRE(address_index);

    BOOST_REQUIRE(Rewind(m_wallet, output));
    const mw::WalletCoin first = GetCoin(m_wallet, output.GetOutputID());
    CheckOwnedMetadata(m_wallet, first, output, address, AMOUNT, *address_index);
    BOOST_CHECK_EQUAL(m_wallet.GetVersion(), FEATURE_V24);

    const mw::WalletCoin persisted = ReadPersistedCoin(m_wallet, output.GetOutputID());
    BOOST_CHECK(persisted == first);
    BOOST_CHECK(!persisted.NeedsPersistenceUpgrade());
    BOOST_CHECK(!persisted.HadPersistedSpendKey());

    BOOST_REQUIRE(Rewind(m_wallet, output));
    BOOST_CHECK(GetCoin(m_wallet, output.GetOutputID()) == first);
    BOOST_CHECK(ReadPersistedCoin(m_wallet, output.GetOutputID()) == first);
}

// A rescan repairs incomplete owned metadata instead of treating a known output as already complete.
BOOST_AUTO_TEST_CASE(RewindRepairsSparseOwnedCoinMetadata)
{
    static constexpr CAmount AMOUNT{5'500'000};
    const StealthAddress address = NewMWEBAddress(m_wallet);
    const mw::Output output = IncomingOutput(address, AMOUNT);
    const std::optional<uint32_t> address_index = Keychain(m_wallet)->LookupAddressIndex(address);
    BOOST_REQUIRE(address_index);

    mw::WalletCoin sparse_coin;
    sparse_coin.address_index = *address_index;
    sparse_coin.amount = AMOUNT;
    sparse_coin.output_id = output.GetOutputID();
    {
        LOCK(m_wallet.cs_wallet);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveToWallet({sparse_coin}));
    }
    BOOST_CHECK(!GetCoin(m_wallet, output.GetOutputID()).shared_secret);

    BOOST_REQUIRE(Rewind(m_wallet, output));
    const mw::WalletCoin repaired = GetCoin(m_wallet, output.GetOutputID());
    CheckOwnedMetadata(m_wallet, repaired, output, address, AMOUNT, *address_index);
    BOOST_CHECK(ReadPersistedCoin(m_wallet, output.GetOutputID()) == repaired);
}

// Recipient metadata may arrive after sender-key rewind and enriches the same external coin without changing ownership.
BOOST_AUTO_TEST_CASE(LateRecipientMetadataEnrichesSentOutput)
{
    static constexpr CAmount AMOUNT{6'600'000};
    const StealthAddress recipient = StealthAddress::Random();
    const SentOutput sent = CreateSentOutput(m_wallet, recipient, AMOUNT, /*sender_index=*/3);

    BOOST_CHECK(!Rewind(m_wallet, sent.output));
    mw::WalletCoin coin = GetCoin(m_wallet, sent.output.GetOutputID());
    BOOST_CHECK(!coin.address);
    BOOST_REQUIRE(coin.shared_secret);

    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.GetMWWallet()->StageWalletCoins({{coin.output_id, coin}});
        m_wallet.GetMWWallet()->StageOutputAddresses({{coin.output_id, recipient}});
        BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveStagedCoinsToWallet({coin.output_id}));
    }

    const mw::WalletCoin enriched = GetCoin(m_wallet, sent.output.GetOutputID());
    BOOST_CHECK(!enriched.IsMine());
    BOOST_REQUIRE(enriched.address);
    BOOST_CHECK(*enriched.address == recipient);
    BOOST_CHECK(enriched.sender_key == coin.sender_key);
    BOOST_CHECK(enriched.shared_secret == coin.shared_secret);
    BOOST_CHECK(enriched.blind == coin.blind);

    BOOST_CHECK(!Rewind(m_wallet, sent.output));
    BOOST_CHECK(GetCoin(m_wallet, sent.output.GetOutputID()) == enriched);
}

// Signing metadata stays staged until commit, then owned and change outputs are classified before sender rewind completes metadata.
BOOST_AUTO_TEST_CASE(StagedOutputMetadataFollowsCommitLifecycle)
{
    static constexpr CAmount OWNED_AMOUNT{7'100'000};
    static constexpr CAmount CHANGE_AMOUNT{7'200'000};
    static constexpr CAmount EXTERNAL_AMOUNT{7'300'000};
    const StealthAddress owned_address = NewMWEBAddress(m_wallet);
    const StealthAddress change_address = Keychain(m_wallet)->DeriveAddress(mw::CHANGE_INDEX);
    const StealthAddress external_address = StealthAddress::Random();
    const SentOutput owned = CreateSentOutput(m_wallet, owned_address, OWNED_AMOUNT, /*sender_index=*/10);
    const SentOutput change = CreateSentOutput(m_wallet, change_address, CHANGE_AMOUNT, /*sender_index=*/11);
    const SentOutput external = CreateSentOutput(m_wallet, external_address, EXTERNAL_AMOUNT, /*sender_index=*/12);

    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.GetMWWallet()->StageWalletCoins({
            {owned.output.GetOutputID(), owned.staged_coin},
            {change.output.GetOutputID(), change.staged_coin},
            {external.output.GetOutputID(), external.staged_coin},
        });
        m_wallet.GetMWWallet()->StageOutputAddresses({
            {owned.output.GetOutputID(), owned_address},
            {change.output.GetOutputID(), change_address},
            {external.output.GetOutputID(), external_address},
        });
    }

    BOOST_CHECK(!HasCoin(m_wallet, owned.output.GetOutputID()));
    BOOST_CHECK(!HasCoin(m_wallet, change.output.GetOutputID()));
    BOOST_CHECK(!HasCoin(m_wallet, external.output.GetOutputID()));

    {
        LOCK(m_wallet.cs_wallet);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveStagedCoinsToWallet({
            owned.output.GetOutputID(),
            change.output.GetOutputID(),
        }));
    }
    BOOST_CHECK(HasCoin(m_wallet, owned.output.GetOutputID()));
    BOOST_CHECK(HasCoin(m_wallet, change.output.GetOutputID()));
    BOOST_CHECK(!HasCoin(m_wallet, external.output.GetOutputID()));

    const mw::WalletCoin owned_coin = GetCoin(m_wallet, owned.output.GetOutputID());
    const std::optional<uint32_t> owned_index = Keychain(m_wallet)->LookupAddressIndex(owned_address);
    BOOST_REQUIRE(owned_index);
    BOOST_CHECK_EQUAL(owned_coin.address_index, *owned_index);
    BOOST_REQUIRE(owned_coin.shared_secret);
    BOOST_CHECK(*owned_coin.shared_secret == mw::DeriveSharedSecret(owned.sender_key, owned_address, OWNED_AMOUNT));

    const mw::WalletCoin change_coin = GetCoin(m_wallet, change.output.GetOutputID());
    BOOST_CHECK(change_coin.IsChange());
    BOOST_REQUIRE(change_coin.shared_secret);
    BOOST_CHECK(*change_coin.shared_secret == mw::DeriveSharedSecret(change.sender_key, change_address, CHANGE_AMOUNT));

    {
        LOCK(m_wallet.cs_wallet);
        BOOST_REQUIRE(m_wallet.GetMWWallet()->SaveStagedCoinsToWallet({external.output.GetOutputID()}));
    }
    const mw::WalletCoin external_before_rewind = GetCoin(m_wallet, external.output.GetOutputID());
    BOOST_CHECK(!external_before_rewind.IsMine());
    BOOST_REQUIRE(external_before_rewind.address);
    BOOST_CHECK(!external_before_rewind.shared_secret);

    BOOST_CHECK(!Rewind(m_wallet, external.output));
    const mw::WalletCoin external_after_rewind = GetCoin(m_wallet, external.output.GetOutputID());
    BOOST_REQUIRE(external_after_rewind.shared_secret);
    BOOST_CHECK(*external_after_rewind.shared_secret == mw::DeriveSharedSecret(external.sender_key, external_address, EXTERNAL_AMOUNT));
    BOOST_CHECK(ReadPersistedCoin(m_wallet, external.output.GetOutputID()) == external_after_rewind);
}

// Scan metadata remains usable while encrypted: rewind works locked, while spend-key derivation waits for unlock.
BOOST_AUTO_TEST_CASE(LockedWalletRewindsAndUnlockRestoresSpendKeyDerivation)
{
    static constexpr CAmount AMOUNT{8'800'000};
    const SecureString passphrase{"rewind-test-passphrase"};
    const StealthAddress address = NewMWEBAddress(m_wallet);
    const mw::Output output = IncomingOutput(address, AMOUNT);
    const std::optional<uint32_t> address_index = Keychain(m_wallet)->LookupAddressIndex(address);
    BOOST_REQUIRE(address_index);

    BOOST_REQUIRE(m_wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(m_wallet.IsLocked());
    BOOST_REQUIRE(Rewind(m_wallet, output));

    const mw::WalletCoin locked_coin = GetCoin(m_wallet, output.GetOutputID());
    BOOST_CHECK(locked_coin.IsMine());
    BOOST_REQUIRE(locked_coin.shared_secret);
    BOOST_CHECK(!Keychain(m_wallet)->CalculateOutputSpendKey(locked_coin));

    BOOST_REQUIRE(m_wallet.Unlock(passphrase));
    const mw::WalletCoin unlocked_coin = GetCoin(m_wallet, output.GetOutputID());
    BOOST_CHECK(unlocked_coin == locked_coin);
    CheckOwnedMetadata(m_wallet, unlocked_coin, output, address, AMOUNT, *address_index);
    BOOST_CHECK(ReadPersistedCoin(m_wallet, output.GetOutputID()) == unlocked_coin);
}

// Sender-key discovery advances monotonically and rescanning an older output never reuses keys.
BOOST_AUTO_TEST_CASE(SenderMetadataAdvancesMonotonicallyAcrossRescans)
{
    static constexpr uint64_t NEWER_INDEX{5};
    static constexpr uint64_t OLDER_INDEX{2};
    const SentOutput newer = CreateSentOutput(m_wallet, StealthAddress::Random(), 9'100'000, NEWER_INDEX);
    const SentOutput older = CreateSentOutput(m_wallet, StealthAddress::Random(), 9'200'000, OLDER_INDEX);

    BOOST_CHECK(!Rewind(m_wallet, newer.output));
    util::Result<SecretKey> next = WITH_LOCK(m_wallet.cs_wallet, return m_wallet.GetMWWallet()->GenerateSenderKey());
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == Keychain(m_wallet)->GetSenderSigningKey(NEWER_INDEX + 1));

    BOOST_CHECK(!Rewind(m_wallet, older.output));
    next = WITH_LOCK(m_wallet.cs_wallet, return m_wallet.GetMWWallet()->GenerateSenderKey());
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == Keychain(m_wallet)->GetSenderSigningKey(NEWER_INDEX + 2));
}

// Persisted rewind metadata survives its disk serialization format and still supports spend-key derivation.
BOOST_AUTO_TEST_CASE(PersistedRewindMetadataRoundTrips)
{
    static constexpr CAmount AMOUNT{10'100'000};
    const StealthAddress address = NewMWEBAddress(m_wallet);
    const mw::Output output = IncomingOutput(address, AMOUNT);

    BOOST_REQUIRE(Rewind(m_wallet, output));
    const mw::WalletCoin persisted = ReadPersistedCoin(m_wallet, output.GetOutputID());
    const std::vector<uint8_t> bytes = persisted.Serialized();
    BOOST_REQUIRE(!bytes.empty());
    BOOST_CHECK_EQUAL(bytes.front(), mw::WalletCoin::LATEST_VERSION);

    const mw::WalletCoin restored = mw::WalletCoin::Deserialize(bytes);
    BOOST_CHECK(restored == persisted);
    BOOST_REQUIRE(restored.address);
    BOOST_CHECK(*restored.address == address);
    BOOST_REQUIRE(restored.shared_secret);
    BOOST_REQUIRE(restored.master_scan_key_id);
    BOOST_CHECK(!restored.NeedsPersistenceUpgrade());
    BOOST_CHECK(!restored.HadPersistedSpendKey());

    const std::optional<SecretKey> spend_key = Keychain(m_wallet)->CalculateOutputSpendKey(restored);
    BOOST_REQUIRE(spend_key);
    BOOST_CHECK(PublicKey::From(*spend_key) == output.GetReceiverPubKey());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
