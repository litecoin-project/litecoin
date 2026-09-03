// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/tx/Output.h>
#include <script/descriptor.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/system.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace wallet {
namespace {

class ToggleFailBatch : public DatabaseBatch
{
private:
    bool* m_writes_succeed;

    bool ReadKey(CDataStream&&, CDataStream&) override { return false; }
    bool WriteKey(CDataStream&&, CDataStream&&, bool) override { return *m_writes_succeed; }
    bool EraseKey(CDataStream&&) override { return *m_writes_succeed; }
    bool HasKey(CDataStream&&) override { return false; }

public:
    explicit ToggleFailBatch(bool* writes_succeed) : m_writes_succeed(writes_succeed) { }

    void Flush() override { }
    void Close() override { }
    bool StartCursor() override { return false; }
    bool ReadAtCursor(CDataStream&, CDataStream&, bool&) override { return false; }
    void CloseCursor() override { }
    bool TxnBegin() override { return false; }
    bool TxnCommit() override { return false; }
    bool TxnAbort() override { return false; }
};

class ToggleFailDatabase : public WalletDatabase
{
public:
    bool writes_succeed{true};

    void Open() override { }
    void AddRef() override { }
    void RemoveRef() override { }
    bool Rewrite(const char* = nullptr) override { return true; }
    bool Backup(const std::string&) const override { return true; }
    void Close() override { }
    void Flush() override { }
    bool PeriodicFlush() override { return true; }
    void IncrementUpdateCounter() override { ++nUpdateCounter; }
    void ReloadDbEnv() override { }
    std::string Filename() override { return "toggle-fail-db"; }
    std::string Format() override { return "toggle-fail-db"; }
    std::unique_ptr<DatabaseBatch> MakeBatch(bool = true) override
    {
        return std::make_unique<ToggleFailBatch>(&writes_succeed);
    }
};

class KeypoolArgGuard
{
public:
    explicit KeypoolArgGuard(int64_t size)
    {
        gArgs.ForceSetArg("-keypool", std::to_string(size));
    }

    ~KeypoolArgGuard()
    {
        gArgs.LockSettings([](util::Settings& settings) {
            settings.forced_settings.erase("keypool");
        });
    }
};

class MWEBKeychainTestingSetup : public TestChain100Setup
{
public:
    CWallet m_wallet;
    CPubKey m_seed;

    MWEBKeychainTestingSetup()
        : m_wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase())
    {
        BOOST_REQUIRE(m_wallet.LoadWallet() == DBErrors::LOAD_OK);
        SetupLegacyWallet(m_wallet);
        m_seed = SetNewSeed(m_wallet);
    }

    void SetupLegacyWallet(CWallet& wallet) const
    {
        wallet.SetupLegacyScriptPubKeyMan();
        WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_MWEB));
    }

    LegacyScriptPubKeyMan& LegacySPKM(CWallet& wallet) const
    {
        LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
        BOOST_REQUIRE(spk_man);
        return *spk_man;
    }

    CPubKey SetNewSeed(CWallet& wallet) const
    {
        LegacyScriptPubKeyMan& spk_man = LegacySPKM(wallet);
        LOCK(spk_man.cs_KeyStore);
        const CPubKey seed = spk_man.GenerateNewSeed();
        spk_man.SetHDSeed(seed);
        return seed;
    }

    void ActivateSeed(CWallet& wallet, const CPubKey& seed) const
    {
        LegacyScriptPubKeyMan& spk_man = LegacySPKM(wallet);
        LOCK(spk_man.cs_KeyStore);
        spk_man.SetHDSeed(seed);
    }

    mw::Keychain::Ptr Keychain(CWallet& wallet) const
    {
        ScriptPubKeyMan* spk_man = wallet.GetScriptPubKeyMan(OutputType::MWEB, false);
        BOOST_REQUIRE(spk_man);
        const mw::Keychain::Ptr keychain = spk_man->GetMWEBKeychain();
        BOOST_REQUIRE(keychain);
        return keychain;
    }

    CKeyID MasterScanKeyId(const mw::Keychain::Ptr& keychain) const
    {
        return PublicKey::From(keychain->GetScanSecret()).GetID();
    }

    util::Result<SecretKey> GenerateSenderKey(CWallet& wallet) const
    {
        LOCK(wallet.cs_wallet);
        return wallet.GetMWWallet()->GenerateSenderKey();
    }

    bool ReadSenderIndex(CWallet& wallet, const CKeyID& master_scan_keyid, uint64_t& next_index) const
    {
        return wallet.GetDatabase().MakeBatch()->Read(
            std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid),
            next_index
        );
    }

    uint64_t ReadSenderIndex(CWallet& wallet, const CKeyID& master_scan_keyid) const
    {
        uint64_t next_index{0};
        BOOST_REQUIRE(ReadSenderIndex(wallet, master_scan_keyid, next_index));
        return next_index;
    }

    void LoadSenderIndexRecord(CWallet& wallet, const CKeyID& master_scan_keyid, uint64_t next_index) const
    {
        CDataStream key(SER_DISK, CLIENT_VERSION);
        key << std::make_pair(DBKeys::MWEB_SENDER_KEY_INDEX, master_scan_keyid);
        CDataStream value(SER_DISK, CLIENT_VERSION);
        value << next_index;

        std::string type;
        std::string error;
        LOCK(wallet.cs_wallet);
        BOOST_REQUIRE_MESSAGE(ReadKeyValue(&wallet, key, value, type, error), error);
        BOOST_CHECK_EQUAL(type, DBKeys::MWEB_SENDER_KEY_INDEX);
    }

    mw::Output SentOutput(const mw::Keychain::Ptr& keychain, uint64_t sender_index, CAmount amount) const
    {
        return mw::Output::Create(
            /*blind_out=*/nullptr,
            keychain->GetSenderSigningKey(sender_index),
            keychain->GetRewindKey(),
            StealthAddress::Random(),
            amount,
            /*extra_data=*/{}
        );
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
};

BOOST_FIXTURE_TEST_SUITE(mweb_keychain_tests, MWEBKeychainTestingSetup)

// A new legacy MWEB keychain caches its master material and reserves indices 0 and 1 before handing out receive addresses.
BOOST_AUTO_TEST_CASE(LegacyKeychainReservesChangeAndPeginAddresses)
{
    LegacyScriptPubKeyMan& spk_man = LegacySPKM(m_wallet);
    const mw::Keychain::Ptr keychain = Keychain(m_wallet);
    CHDChain chain;
    {
        LOCK(spk_man.cs_KeyStore);
        chain = spk_man.GetHDChain();
    }

    BOOST_CHECK_EQUAL(chain.nVersion, CHDChain::VERSION_HD_MWEB_RECEIVE);
    BOOST_CHECK_EQUAL(chain.nMWEBIndexCounter, 2U);
    BOOST_REQUIRE(chain.mweb_scan_key);
    BOOST_REQUIRE(chain.mweb_spend_pubkey);
    BOOST_CHECK(*chain.mweb_scan_key == keychain->GetScanSecret());
    BOOST_CHECK(keychain->HasSpendPubKey());
    BOOST_CHECK(keychain->HasSpendSecret());

    const StealthAddress change = keychain->DeriveAddress(mw::CHANGE_INDEX);
    const StealthAddress pegin = keychain->DeriveAddress(mw::PEGIN_INDEX);
    BOOST_CHECK(keychain->LookupAddressIndex(change) == mw::CHANGE_INDEX);
    BOOST_CHECK(keychain->LookupAddressIndex(pegin) == mw::PEGIN_INDEX);

    const util::Result<CTxDestination> destination = m_wallet.GetNewDestination(OutputType::MWEB, "");
    BOOST_REQUIRE(destination);
    BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*destination));
    const StealthAddress& receive = std::get<StealthAddress>(*destination);
    BOOST_CHECK(receive == keychain->DeriveAddress(2));
    BOOST_CHECK(keychain->LookupAddressIndex(receive) == 2U);
}

// Sender keys are deterministic, unique, and durably advance the per-keychain sequence before being returned.
BOOST_AUTO_TEST_CASE(SenderKeysAdvanceAndPersistSequentially)
{
    const mw::Keychain::Ptr keychain = Keychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);

    const util::Result<SecretKey> first = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first);
    BOOST_CHECK(*first == keychain->GetSenderSigningKey(0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 1U);

    const util::Result<SecretKey> second = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(second);
    BOOST_CHECK(*second == keychain->GetSenderSigningKey(1));
    BOOST_CHECK(*second != *first);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 2U);

    const util::Result<SecretKey> third = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(third);
    BOOST_CHECK(*third == keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 3U);
    BOOST_CHECK_EQUAL(m_wallet.GetVersion(), FEATURE_V24);

    int persisted_min_version{0};
    BOOST_REQUIRE(m_wallet.GetDatabase().MakeBatch()->Read(DBKeys::MINVERSION, persisted_min_version));
    BOOST_CHECK_EQUAL(persisted_min_version, FEATURE_V24);
}

// Loading the persisted sender-index record resumes at the next unused key instead of restarting the sequence.
BOOST_AUTO_TEST_CASE(PersistedSenderIndexRestoresSequence)
{
    const mw::Keychain::Ptr keychain = Keychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);
    BOOST_REQUIRE(GenerateSenderKey(m_wallet));
    BOOST_REQUIRE(GenerateSenderKey(m_wallet));
    const uint64_t persisted_next_index = ReadSenderIndex(m_wallet, master_scan_keyid);
    BOOST_REQUIRE_EQUAL(persisted_next_index, 2U);

    WITH_LOCK(m_wallet.cs_wallet, m_wallet.GetMWWallet()->LoadNextSenderKeyIndex(master_scan_keyid, 0));
    LoadSenderIndexRecord(m_wallet, master_scan_keyid, persisted_next_index);

    const util::Result<SecretKey> restored_next = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(restored_next);
    BOOST_CHECK(*restored_next == keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 3U);
}

// Locking removes spend secrets but leaves scan-derived rewind and sender sequences available and stable across unlock.
BOOST_AUTO_TEST_CASE(LockAndUnlockPreserveScanDerivedSequence)
{
    const SecureString passphrase{"mweb-keychain-passphrase"};
    const mw::Keychain::Ptr initial_keychain = Keychain(m_wallet);
    const SecretKey scan_secret = initial_keychain->GetScanSecret();
    const SecretKey rewind_key = initial_keychain->GetRewindKey();
    const CKeyID master_scan_keyid = MasterScanKeyId(initial_keychain);

    const util::Result<SecretKey> before_lock = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(before_lock);
    BOOST_CHECK(*before_lock == initial_keychain->GetSenderSigningKey(0));

    BOOST_REQUIRE(m_wallet.EncryptWallet(passphrase));
    BOOST_REQUIRE(m_wallet.IsLocked());
    const mw::Keychain::Ptr locked_keychain = Keychain(m_wallet);
    BOOST_CHECK(locked_keychain->GetScanSecret() == scan_secret);
    BOOST_CHECK(locked_keychain->GetRewindKey() == rewind_key);
    BOOST_CHECK(locked_keychain->HasSpendPubKey());
    BOOST_CHECK(!locked_keychain->HasSpendSecret());

    const util::Result<SecretKey> while_locked = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(while_locked);
    BOOST_CHECK(*while_locked == locked_keychain->GetSenderSigningKey(1));

    BOOST_REQUIRE(m_wallet.Unlock(passphrase));
    const mw::Keychain::Ptr unlocked_keychain = Keychain(m_wallet);
    BOOST_CHECK(unlocked_keychain->GetScanSecret() == scan_secret);
    BOOST_CHECK(unlocked_keychain->GetRewindKey() == rewind_key);
    BOOST_CHECK(unlocked_keychain->HasSpendPubKey());
    BOOST_CHECK(unlocked_keychain->HasSpendSecret());

    const util::Result<SecretKey> after_unlock = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(after_unlock);
    BOOST_CHECK(*after_unlock == unlocked_keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 3U);
}

// Sender indices are keyed by the master scan key, so rotating away and back resumes each seed's independent sequence.
BOOST_AUTO_TEST_CASE(SeedRotationKeepsSenderSequencesIndependent)
{
    const mw::Keychain::Ptr first_keychain = Keychain(m_wallet);
    const CKeyID first_master_id = MasterScanKeyId(first_keychain);
    const util::Result<SecretKey> first_seed_first = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first_seed_first);
    BOOST_CHECK(*first_seed_first == first_keychain->GetSenderSigningKey(0));
    const util::Result<SecretKey> first_seed_second = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first_seed_second);
    BOOST_CHECK(*first_seed_second == first_keychain->GetSenderSigningKey(1));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_master_id), 2U);

    const CPubKey second_seed = SetNewSeed(m_wallet);
    const mw::Keychain::Ptr second_keychain = Keychain(m_wallet);
    const CKeyID second_master_id = MasterScanKeyId(second_keychain);
    BOOST_CHECK(second_seed != m_seed);
    BOOST_CHECK(second_master_id != first_master_id);

    const util::Result<SecretKey> second_seed_first = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(second_seed_first);
    BOOST_CHECK(*second_seed_first == second_keychain->GetSenderSigningKey(0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_master_id), 1U);

    ActivateSeed(m_wallet, m_seed);
    const mw::Keychain::Ptr restored_first_keychain = Keychain(m_wallet);
    BOOST_CHECK(MasterScanKeyId(restored_first_keychain) == first_master_id);
    const util::Result<SecretKey> first_seed_resumed = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(first_seed_resumed);
    BOOST_CHECK(*first_seed_resumed == restored_first_keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, first_master_id), 3U);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, second_master_id), 1U);
}

// Sender-output discovery covers exactly the configured lookahead and expands it after a boundary match advances the index.
BOOST_AUTO_TEST_CASE(SenderLookaheadAdvancesAtItsBoundary)
{
    const KeypoolArgGuard keypool_size{/*size=*/3};
    const mw::Keychain::Ptr keychain = Keychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);
    const mw::Output boundary = SentOutput(keychain, /*sender_index=*/2, /*amount=*/2'000'000);
    const mw::Output initially_beyond = SentOutput(keychain, /*sender_index=*/3, /*amount=*/3'000'000);

    BOOST_CHECK(!Rewind(m_wallet, initially_beyond));
    {
        LOCK(m_wallet.cs_wallet);
        mw::WalletCoin coin;
        BOOST_CHECK(!m_wallet.GetMWEBWalletCoin(initially_beyond.GetOutputID(), coin));
    }

    BOOST_CHECK(!Rewind(m_wallet, boundary));
    const mw::WalletCoin boundary_coin = GetCoin(m_wallet, boundary.GetOutputID());
    BOOST_REQUIRE(boundary_coin.sender_key);
    BOOST_CHECK(*boundary_coin.sender_key == keychain->GetSenderSigningKey(2));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 3U);

    BOOST_CHECK(!Rewind(m_wallet, initially_beyond));
    const mw::WalletCoin discovered_coin = GetCoin(m_wallet, initially_beyond.GetOutputID());
    BOOST_REQUIRE(discovered_coin.sender_key);
    BOOST_CHECK(*discovered_coin.sender_key == keychain->GetSenderSigningKey(3));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), 4U);

    const util::Result<SecretKey> next = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(next);
    BOOST_CHECK(*next == keychain->GetSenderSigningKey(4));
}

// The terminal sender index is usable once and then reports exhaustion without wrapping or changing persisted state.
BOOST_AUTO_TEST_CASE(SenderIndexExhaustionDoesNotWrap)
{
    const mw::Keychain::Ptr keychain = Keychain(m_wallet);
    const CKeyID master_scan_keyid = MasterScanKeyId(keychain);
    const uint64_t last_index = std::numeric_limits<uint64_t>::max() - 1;
    WITH_LOCK(m_wallet.cs_wallet, m_wallet.GetMWWallet()->LoadNextSenderKeyIndex(master_scan_keyid, last_index));

    const util::Result<SecretKey> last_key = GenerateSenderKey(m_wallet);
    BOOST_REQUIRE(last_key);
    BOOST_CHECK(*last_key == keychain->GetSenderSigningKey(last_index));
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), std::numeric_limits<uint64_t>::max());

    const util::Result<SecretKey> exhausted = GenerateSenderKey(m_wallet);
    BOOST_CHECK(!exhausted);
    BOOST_CHECK(util::ErrorString(exhausted).original.find("exhausted") != std::string::npos);
    BOOST_CHECK_EQUAL(ReadSenderIndex(m_wallet, master_scan_keyid), std::numeric_limits<uint64_t>::max());
}

// A failed index write does not consume a sender key; retrying returns the same next key and resumes normal progression.
BOOST_AUTO_TEST_CASE(FailedSenderIndexWriteDoesNotConsumeKey)
{
    auto database = std::make_unique<ToggleFailDatabase>();
    ToggleFailDatabase* failing_database = database.get();
    CWallet wallet(m_node.chain.get(), "", m_args, std::move(database));
    SetupLegacyWallet(wallet);
    WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_V24));
    SetNewSeed(wallet);
    const mw::Keychain::Ptr keychain = Keychain(wallet);

    failing_database->writes_succeed = false;
    const util::Result<SecretKey> failed = GenerateSenderKey(wallet);
    BOOST_CHECK(!failed);
    BOOST_CHECK(util::ErrorString(failed).original.find("sender key index") != std::string::npos);

    failing_database->writes_succeed = true;
    const util::Result<SecretKey> retried = GenerateSenderKey(wallet);
    BOOST_REQUIRE(retried);
    BOOST_CHECK(*retried == keychain->GetSenderSigningKey(0));
    const util::Result<SecretKey> following = GenerateSenderKey(wallet);
    BOOST_REQUIRE(following);
    BOOST_CHECK(*following == keychain->GetSenderSigningKey(1));
}

// Without an MWEB keychain, callers still receive independent ephemeral sender keys and no wallet state is persisted.
BOOST_AUTO_TEST_CASE(MissingKeychainUsesEphemeralSenderKeys)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    const int original_version = wallet.GetVersion();

    const util::Result<SecretKey> first = GenerateSenderKey(wallet);
    const util::Result<SecretKey> second = GenerateSenderKey(wallet);
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(second);
    BOOST_CHECK(!first->IsNull());
    BOOST_CHECK(!second->IsNull());
    BOOST_CHECK(*first != *second);
    BOOST_CHECK_EQUAL(wallet.GetVersion(), original_version);
    BOOST_CHECK_EQUAL(wallet.GetDatabase().nUpdateCounter, 0U);
}

// Non-active descriptor keychains remain available for rewinding their outputs and keep sender indices separate from the active keychain.
BOOST_AUTO_TEST_CASE(InactiveDescriptorKeychainRemainsDiscoverable)
{
    static constexpr uint32_t ADDRESS_INDEX{7};
    static constexpr uint64_t SENDER_INDEX{4};
    static constexpr CAmount RECEIVED_AMOUNT{4'000'000};
    static constexpr CAmount SENT_AMOUNT{5'000'000};
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);
    {
        LOCK(wallet.cs_wallet);
        wallet.LoadMinVersion(FEATURE_MWEB);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }
    const mw::Keychain::Ptr active_keychain = wallet.GetMWWallet()->GetActiveKeychain();
    BOOST_REQUIRE(active_keychain);
    const CKeyID active_master_id = MasterScanKeyId(active_keychain);

    CKey scan_key;
    scan_key.MakeNewKey(true);
    CKey spend_key;
    spend_key.MakeNewKey(true);
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> parsed = Parse(
        strprintf("mweb(%s,%s,%u)", EncodeSecret(scan_key), EncodeSecret(spend_key), ADDRESS_INDEX),
        provider,
        error,
        /*require_checksum=*/false
    );
    BOOST_REQUIRE_MESSAGE(parsed, error);
    WalletDescriptor descriptor(std::move(parsed), /*creation_time=*/0, /*range_start=*/0, /*range_end=*/1, /*next_index=*/1);
    ScriptPubKeyMan* inactive_spk_man{nullptr};
    {
        LOCK(wallet.cs_wallet);
        inactive_spk_man = wallet.AddWalletDescriptor(descriptor, provider, "", /*internal=*/false);
    }
    BOOST_REQUIRE(inactive_spk_man);
    const mw::Keychain::Ptr inactive_keychain = inactive_spk_man->GetMWEBKeychain();
    BOOST_REQUIRE(inactive_keychain);
    const CKeyID inactive_master_id = MasterScanKeyId(inactive_keychain);
    BOOST_CHECK(inactive_master_id != active_master_id);
    BOOST_CHECK(wallet.GetMWWallet()->GetKeychain(inactive_master_id) == inactive_keychain);

    const StealthAddress inactive_address = inactive_keychain->DeriveAddress(ADDRESS_INDEX);
    const mw::Output received = mw::Output::Create(
        /*blind_out=*/nullptr,
        SecretKey::Random(),
        SecretKey::Random(),
        inactive_address,
        RECEIVED_AMOUNT,
        /*extra_data=*/{}
    );
    BOOST_REQUIRE(Rewind(wallet, received));
    const mw::WalletCoin received_coin = GetCoin(wallet, received.GetOutputID());
    BOOST_CHECK_EQUAL(received_coin.address_index, ADDRESS_INDEX);
    BOOST_REQUIRE(received_coin.master_scan_key_id);
    BOOST_CHECK(*received_coin.master_scan_key_id == inactive_master_id);
    const std::optional<SecretKey> output_spend_key = inactive_keychain->CalculateOutputSpendKey(received_coin);
    BOOST_REQUIRE(output_spend_key);
    BOOST_CHECK(PublicKey::From(*output_spend_key) == received.GetReceiverPubKey());

    const mw::Output sent = SentOutput(inactive_keychain, SENDER_INDEX, SENT_AMOUNT);
    BOOST_CHECK(!Rewind(wallet, sent));
    const mw::WalletCoin sent_coin = GetCoin(wallet, sent.GetOutputID());
    BOOST_REQUIRE(sent_coin.sender_key);
    BOOST_CHECK(*sent_coin.sender_key == inactive_keychain->GetSenderSigningKey(SENDER_INDEX));
    BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, inactive_master_id), SENDER_INDEX + 1);

    uint64_t active_next_index{0};
    BOOST_CHECK(!ReadSenderIndex(wallet, active_master_id, active_next_index));
    const util::Result<SecretKey> active_sender_key = GenerateSenderKey(wallet);
    BOOST_REQUIRE(active_sender_key);
    BOOST_CHECK(*active_sender_key == active_keychain->GetSenderSigningKey(0));
    BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, active_master_id), 1U);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
