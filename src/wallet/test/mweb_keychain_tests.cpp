// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <mweb/mweb_wallet.h>
#include <mw/models/tx/Output.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/system.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/test/psbt_test_utils.h>
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

    mw::Keychain::Ptr ImportMWEBDescriptor(CWallet& wallet, const std::string& descriptor) const
    {
        FlatSigningProvider provider;
        std::string error;
        auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
        BOOST_REQUIRE_MESSAGE(parsed, error);
        const bool ranged = parsed->IsRange();
        WalletDescriptor wallet_descriptor(std::move(parsed), 0, 0, ranged ? 10 : 1, 0);
        LOCK(wallet.cs_wallet);
        wallet.LoadMinVersion(FEATURE_MWEB);
        auto* manager = wallet.AddWalletDescriptor(wallet_descriptor, provider, "", /*internal=*/false);
        BOOST_REQUIRE(manager);
        BOOST_REQUIRE(manager->GetMWEBKeychain());
        return manager->GetMWEBKeychain();
    }

    // Exercise both wallet signing entry points with stored and recovered address metadata.
    void CheckDescriptorSigning(CWallet& wallet, const StealthAddress& address) const
    {
        const mw::Output received = mw::Output::Create(
            nullptr, SecretKey::Random(), SecretKey::Random(), address, 100'000, {});
        BOOST_REQUIRE(Rewind(wallet, received));
        const mw::WalletCoin original = GetCoin(wallet, received.GetOutputID());

        for (int metadata = 0; metadata < 3; ++metadata) {
            BOOST_TEST_CONTEXT("metadata variant " << metadata) {
                mw::WalletCoin coin = original;
                if (metadata > 0) coin.address.reset();
                if (metadata > 1) coin.shared_secret.reset();
                LOCK(wallet.cs_wallet);
                wallet.GetMWWallet()->LoadToWallet(coin);

                CheckCoinSigning(wallet, received);
            }
        }
    }

    // Spend the stored coin through both wallet signing paths and validate the finalized transactions.
    void CheckCoinSigning(CWallet& wallet, const mw::Output& received) const
    {
        LOCK(wallet.cs_wallet);
        CMutableTransaction tx;
        tx.mweb_tx.inputs.push_back(mw::MutableInput::FromOutput(received));
        mw::MutableOutput output;
        output.address = StealthAddress::Random();
        output.amount = 90'000;
        tx.mweb_tx.outputs.push_back(output);
        mw::MutableKernel kernel;
        kernel.fee = 10'000;
        tx.mweb_tx.kernels.push_back(kernel);
        PartiallySignedTransaction psbt(tx, 2);
        // The updater supplies the key-exchange field; SetupFromTx omits it.
        psbt.inputs[0].mweb_key_exchange_pubkey = received.GetKeyExchangePubKey();

        const bool signed_raw = wallet.SignTransaction(tx);
        BOOST_CHECK(signed_raw);
        if (signed_raw) {
            BOOST_CHECK(tx.mweb_tx.IsFinal());
            BOOST_CHECK(!CTransaction{tx}.mweb_tx.m_transaction->Validate());
        }

        bool complete{false};
        BOOST_CHECK(wallet.FillPSBT(psbt, complete, SIGHASH_ALL) == TransactionError::OK);
        BOOST_CHECK(complete);
        if (complete) {
            const auto finalized = FinalizePSBT(psbt);
            BOOST_REQUIRE(finalized);
            BOOST_CHECK(!CTransaction{*finalized}.mweb_tx.m_transaction->Validate());
            BOOST_CHECK(psbt.inputs[0].mweb_output_pubkey == received.GetReceiverPubKey());
        }
    }

    // Read the durable coin independently of the wallet's in-memory metadata.
    mw::WalletCoin ReadPersistedCoin(CWallet& wallet, const mw::Hash& output_id) const
    {
        mw::WalletCoin coin;
        BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(std::make_pair(DBKeys::COIN, output_id), coin));
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
    const auto inactive_keychains = wallet.GetMWWallet()->GetKeychains(inactive_master_id);
    BOOST_REQUIRE_EQUAL(inactive_keychains.size(), 1U);
    BOOST_CHECK(inactive_keychains[0] == inactive_keychain);

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

// Different spend branches sharing a scan key must each sign raw transactions and PSBTs, even when their coin address needs recovery.
BOOST_AUTO_TEST_CASE(SharedScanDescriptorsSignTheirOwnOutputs)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet.cs_wallet, wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    const auto first = test::MWEBTestKeys::Create('1', '2');
    const auto second = test::MWEBTestKeys::Create('1', '3');
    ImportMWEBDescriptor(wallet, first.Descriptor(7));
    ImportMWEBDescriptor(wallet, second.Descriptor(7));

    CheckDescriptorSigning(wallet, first.Address(7));
    CheckDescriptorSigning(wallet, second.Address(7));
}

// A watch-only manager must not mask a signing manager for the same address, including direct-subaddress imports without master spend keys.
BOOST_AUTO_TEST_CASE(SharedScanSigningSkipsWatchOnlyManagers)
{
    KeypoolArgGuard keypool_size{10};
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet.cs_wallet, wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    const auto keys = test::MWEBTestKeys::Create();
    const std::string scan = EncodeSecret(test::MWEBTestKeys::ToCKey(keys.scan_secret));
    const std::string spend = EncodeSecret(test::MWEBTestKeys::ToCKey(keys.master_spend_secret));
    const std::string spend_pubkey = PublicKey::From(keys.master_spend_secret).ToHex();
    const auto watch = ImportMWEBDescriptor(wallet, strprintf("mweb(%s,%s,7)", scan, spend_pubkey));
    const auto ranged = ImportMWEBDescriptor(wallet, strprintf("mweb(%s,%s,*)", scan, spend));
    mw::WalletCoin coin;
    coin.output_id = mw::Hash::ValueOf(7);
    coin.amount = 100'000;
    coin.address_index = 7;
    coin.master_scan_key_id = PublicKey::From(keys.scan_secret).GetID();
    coin.shared_secret = test::TestSecret('4');
    StealthAddress address;
    BOOST_REQUIRE(wallet.GetMWWallet()->GetStealthAddress(coin, address));
    BOOST_CHECK(address == keys.Address(7));
    {
        LOCK(wallet.cs_wallet);
        wallet.GetMWWallet()->LoadToWallet(coin);
        CMutableTransaction tx;
        tx.mweb_tx.inputs.push_back(mw::MutableInput::FromWalletCoin(coin));
        BOOST_REQUIRE(wallet.CompleteMWEBInputData(tx, {}));
        BOOST_REQUIRE(tx.mweb_tx.inputs[0].spend_key);
        BOOST_CHECK(PublicKey::From(*tx.mweb_tx.inputs[0].spend_key) == keys.OutputPubKey(7, *coin.shared_secret));
    }

    const auto direct = ImportMWEBDescriptor(wallet, strprintf("mweb(%s,%s)", scan,
        EncodeSecret(test::MWEBTestKeys::ToCKey(keys.SubaddressSpendSecret(8)))));
    BOOST_CHECK(!watch->HasSpendSecret());
    BOOST_CHECK(!direct->HasSpendPubKey());
    CheckDescriptorSigning(wallet, keys.Address(7));
    CheckDescriptorSigning(wallet, keys.Address(8));

    const CKeyID scan_id = PublicKey::From(keys.scan_secret).GetID();
    test::MockMWEBKeyStore keystore;
    // Force the non-signing candidate first regardless of manager allocation order.
    keystore.m_keychains[scan_id] = {watch, ranged, direct};
    for (uint32_t index : {7U, 8U}) {
        const SecretKey shared_secret = test::TestSecret('4');
        PSBTInput input(2);
        input.mweb_output_id = mw::Hash::ValueOf(index);
        input.mweb_output_pubkey = keys.OutputPubKey(index, shared_secret);
        input.mweb_shared_secret = shared_secret;
        // A public-spend descriptor must select a wallet manager without any wallet coin.
        input.mweb_address_descriptor = strprintf("mweb(%s,%s,%u)", scan, spend_pubkey, index);
        const auto result = ResolveMWEBInputKeys(input, keystore);
        BOOST_REQUIRE(result);
        BOOST_REQUIRE(result->has_value());
        BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);
    }

    // The direct descriptor must also work without a ranged manager that could derive its key.
    keystore.m_keychains[scan_id] = {watch, direct};
    PSBTInput input(2);
    input.mweb_output_id = mw::Hash::ValueOf(8);
    input.mweb_shared_secret = test::TestSecret('4');
    input.mweb_output_pubkey = keys.OutputPubKey(8, *input.mweb_shared_secret);
    input.mweb_address_descriptor = strprintf("mweb(%s,%s)", scan, keys.Address(8).GetSpendPubKey().ToHex());
    const auto result = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE(result->has_value());
    BOOST_CHECK(PublicKey::From(**result) == *input.mweb_output_pubkey);

    // The shared scan secret alone remains insufficient when no manager holds the spend key.
    keystore.m_keychains[scan_id] = {watch};
    const auto watch_only = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(watch_only);
    BOOST_CHECK(!watch_only->has_value());
}

// Shared scan IDs must not guess an address or spend key when neither the stored coin nor its input identifies the spend branch.
BOOST_AUTO_TEST_CASE(SharedScanSigningRequiresUnambiguousCoinData)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet.cs_wallet, wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    const auto first = test::MWEBTestKeys::Create('1', '2');
    const auto second = test::MWEBTestKeys::Create('1', '3');
    const auto first_chain = ImportMWEBDescriptor(wallet, first.Descriptor(7));
    const auto second_chain = ImportMWEBDescriptor(wallet, second.Descriptor(7));
    const CKeyID scan_id = PublicKey::From(first.scan_secret).GetID();
    mw::WalletCoin coin;
    coin.output_id = mw::Hash::ValueOf(7);
    coin.amount = 100'000;
    coin.address_index = 7;
    coin.master_scan_key_id = scan_id;
    coin.shared_secret = test::TestSecret('4');
    LOCK(wallet.cs_wallet);
    wallet.GetMWWallet()->LoadToWallet(coin);

    StealthAddress address;
    BOOST_CHECK(!wallet.GetMWWallet()->GetStealthAddress(coin, address));
    CMutableTransaction tx;
    tx.mweb_tx.inputs.push_back(mw::MutableInput::FromWalletCoin(coin));
    BOOST_REQUIRE(wallet.CompleteMWEBInputData(tx, {}));
    BOOST_CHECK(!tx.mweb_tx.inputs[0].spend_key);

    test::MockMWEBKeyStore keystore;
    keystore.m_keychains[scan_id] = {first_chain, second_chain};
    keystore.m_coins[coin.output_id] = coin;
    PSBTInput input(2);
    input.mweb_output_id = coin.output_id;
    const auto unresolved = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(unresolved);
    BOOST_CHECK(!unresolved->has_value());
    BOOST_CHECK(input.mweb_shared_secret == coin.shared_secret);

    // Supplying the actual output pubkey resolves the ambiguity in either path.
    const PublicKey output_pubkey = second.OutputPubKey(7, *coin.shared_secret);
    tx.mweb_tx.inputs[0].output_pubkey = output_pubkey;
    BOOST_REQUIRE(wallet.CompleteMWEBInputData(tx, {}));
    BOOST_REQUIRE(tx.mweb_tx.inputs[0].spend_key);
    BOOST_CHECK(PublicKey::From(*tx.mweb_tx.inputs[0].spend_key) == output_pubkey);
    input.mweb_output_pubkey = output_pubkey;
    const auto resolved = ResolveMWEBInputKeys(input, keystore);
    BOOST_REQUIRE(resolved);
    BOOST_REQUIRE(resolved->has_value());
    BOOST_CHECK(PublicKey::From(**resolved) == output_pubkey);
}

// A payment to another keychain retains the recipient's scan ID, the sender's history, and both raw and PSBT spending capability.
BOOST_AUTO_TEST_CASE(SelfPaymentBetweenKeychainsRemainsSpendable)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet.cs_wallet, wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    const auto first = test::MWEBTestKeys::Create('1', '2');
    const auto second = test::MWEBTestKeys::Create('3', '4');
    const auto first_chain = ImportMWEBDescriptor(wallet, first.Descriptor(7));
    const auto second_chain = ImportMWEBDescriptor(wallet, second.Descriptor(7));

    for (const auto& sender : {first_chain, second_chain}) {
        const auto recipient = sender == first_chain ? second_chain : first_chain;
        const auto address = recipient->DeriveAddress(7);
        const SecretKey sender_key = sender->GetSenderSigningKey(0);
        const mw::Output output = mw::Output::Create(nullptr, sender_key, sender->GetRewindKey(), address, 100'000, {});
        BOOST_REQUIRE(Rewind(wallet, output));

        mw::WalletCoin expected;
        BOOST_REQUIRE(recipient->RewindOutput(output, expected));
        expected.sender_key = sender_key;
        BOOST_CHECK(GetCoin(wallet, output.GetOutputID()) == expected);
        BOOST_CHECK(ReadPersistedCoin(wallet, output.GetOutputID()) == expected);
        BOOST_CHECK_EQUAL(ReadSenderIndex(wallet, MasterScanKeyId(sender)), 1U);
        CheckCoinSigning(wallet, output);

        BOOST_REQUIRE(Rewind(wallet, output));
        BOOST_CHECK(GetCoin(wallet, output.GetOutputID()) == expected);
        BOOST_CHECK(ReadPersistedCoin(wallet, output.GetOutputID()) == expected);
    }
}

// Committing a staged payment to another keychain's change address binds it to the recipient before sender rewind runs.
BOOST_AUTO_TEST_CASE(SelfPaymentToAnotherKeychainsChangeRemainsSpendable)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);
    WITH_LOCK(wallet.cs_wallet, wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS));
    const auto sender = ImportMWEBDescriptor(wallet, test::MWEBTestKeys::Create('1', '2').Descriptor(7));
    const auto recipient = ImportMWEBDescriptor(wallet, test::MWEBTestKeys::Create('3', '4').Descriptor(mw::CHANGE_INDEX));
    const auto address = recipient->DeriveAddress(mw::CHANGE_INDEX);
    const SecretKey sender_key = sender->GetSenderSigningKey(0);
    mw::WalletCoin staged;
    BlindingFactor blind;
    const mw::Output output = mw::Output::Create(&blind, sender_key, sender->GetRewindKey(), address, 100'000, {});
    staged.output_id = output.GetOutputID();
    staged.amount = 100'000;
    staged.blind = blind;
    staged.sender_key = sender_key;
    {
        LOCK(wallet.cs_wallet);
        wallet.GetMWWallet()->StageWalletCoins({{staged.output_id, staged}});
        wallet.GetMWWallet()->StageOutputAddresses({{staged.output_id, address}});
        BOOST_REQUIRE(wallet.GetMWWallet()->SaveStagedCoinsToWallet({staged.output_id}));
    }

    mw::WalletCoin expected;
    BOOST_REQUIRE(recipient->RewindOutput(output, expected));
    expected.sender_key = sender_key;
    BOOST_CHECK(GetCoin(wallet, output.GetOutputID()) == expected);
    CheckCoinSigning(wallet, output);
    BOOST_REQUIRE(Rewind(wallet, output));
    BOOST_CHECK(GetCoin(wallet, output.GetOutputID()) == expected);
    BOOST_CHECK(ReadPersistedCoin(wallet, output.GetOutputID()) == expected);
    CheckCoinSigning(wallet, output);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
