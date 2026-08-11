// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>
#include <mweb/mweb_wallet.h>

#include <algorithm>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <stdint.h>
#include <vector>

#include <interfaces/chain.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <test_framework/TxBuilder.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

using node::MAX_BLOCKFILE_SIZE;
using node::UnlinkPrunedFiles;

namespace wallet {
RPCHelpMan importmulti();
RPCHelpMan dumpwallet();
RPCHelpMan importwallet();

// Ensure that fee levels defined in the wallet are at least as high
// as the default levels for node policy.
static_assert(DEFAULT_TRANSACTION_MINFEE >= DEFAULT_MIN_RELAY_TX_FEE, "wallet minimum fee is smaller than default relay fee");
static_assert(WALLET_INCREMENTAL_RELAY_FEE >= DEFAULT_INCREMENTAL_RELAY_FEE, "wallet incremental fee is smaller than default incremental relay fee");

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static const std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context)
{
    DatabaseOptions options;
    options.create_flags = WALLET_FLAG_DESCRIPTORS;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database = MakeWalletDatabase("", options, status, error);
    auto wallet = CWallet::Create(context, "", std::move(database), options.create_flags, error, warnings);
    NotifyWalletLoaded(context, wallet);
    return wallet;
}

static void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet)
{
    SyncWithValidationInterfaceQueue();
    wallet->m_chain_notifications_handler.reset();
    UnloadWallet(std::move(wallet));
}

static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey)
{
    CMutableTransaction mtx;
    mtx.vout.push_back({from.vout[index].nValue - DEFAULT_TRANSACTION_MAXFEE, pubkey});
    mtx.vin.push_back({CTxIn{from.GetHash(), index}});
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    std::map<AnyOutputID, AnyCoin> coins;
    Coin coin;
    coin.out = from.vout[index];
    coins[mtx.vin[0].prevout] = AnyCoin{mtx.vin[0].prevout, coin};
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(mtx, &keystore, coins, SIGHASH_ALL, input_errors));
    return mtx;
}

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    if (!wallet.AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());

    // Verify ScanForWalletTransactions fails to read an unknown start block.
    {
        CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/{}, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(m_node.chain.get(), "", m_args, CreateMockWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        std::chrono::steady_clock::time_point fake_time;
        reserver.setNow([&] { fake_time += 60s; return fake_time; });
        reserver.reserve();

        {
            CBlockLocator locator;
            BOOST_CHECK(!WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(locator.IsNull());
        }

        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/true);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 100 * COIN);

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(!locator.IsNull());
        }
    }

    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 50 * COIN);
    }

    // Prune the remaining block file.
    {
        LOCK(cs_main);
        file_number = newTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    UnlinkPrunedFiles({file_number});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.last_failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }
}

BOOST_FIXTURE_TEST_CASE(importmulti_rescan, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());

    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    UnlinkPrunedFiles({file_number});

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        wallet->SetupLegacyScriptPubKeyMan();
        WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(newTip->nHeight, newTip->GetBlockHash()));
        WalletContext context;
        context.args = &m_args;
        AddWallet(context, wallet);
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp", newTip->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti().HandleRequest(request);
        BOOST_CHECK_EQUAL(response.write(),
            strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":\"Rescan failed for key with creation "
                      "timestamp %d. There was an error reading a block from time %d, which is after or within %d "
                      "seconds of key creation, and could contain transactions pertaining to the key. As a result, "
                      "transactions and coins using this key may not appear in the wallet. This error could be caused "
                      "by pruning or data corruption (see litecoind log for details) and could be dealt with by "
                      "downloading and rescanning the relevant blocks (see -reindex option and rescanblockchain "
                      "RPC).\"}},{\"success\":true}]",
                              0, oldTip->GetBlockTimeMax(), TIMESTAMP_WINDOW));
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup)
{
    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockTimeMax() + 5);
    SetMockTime(BLOCK_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + TIMESTAMP_WINDOW;
    SetMockTime(KEY_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    std::string backup_file = fs::PathToString(m_args.GetDataDirNet() / "wallet.backup");

    // Import key into wallet and call dumpwallet to create backup file.
    {
        WalletContext context;
        context.args = &m_args;
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        {
            auto spk_man = wallet->GetOrCreateLegacyScriptPubKeyMan();
            LOCK2(wallet->cs_wallet, spk_man->cs_KeyStore);
            spk_man->mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime = KEY_TIME;
            spk_man->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

            AddWallet(context, wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(backup_file);

        wallet::dumpwallet().HandleRequest(request);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        LOCK(wallet->cs_wallet);
        wallet->SetupLegacyScriptPubKeyMan();

        WalletContext context;
        context.args = &m_args;
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(context, wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        wallet::importwallet().HandleRequest(request);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);

        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 3U);
        BOOST_CHECK_EQUAL(m_coinbase_txns.size(), 103U);
        for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
            bool found = wallet->GetWalletTx(m_coinbase_txns[i]->GetHash());
            bool expected = i >= 100;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }
}

// Check that GetImmatureCredit() returns a newly calculated value instead of
// the cached value after a MarkDirty() call.
//
// This is a regression test written to verify a bugfix for the immature credit
// function. Similar tests probably should be written for the other credit and
// debit functions.
BOOST_FIXTURE_TEST_CASE(coin_mark_dirty_immature_credit, TestChain100Setup)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());

    LOCK(wallet.cs_wallet);
    LOCK(Assert(m_node.chainman)->GetMutex());

    auto& tx = m_coinbase_txns.back();
    auto [it, _] = wallet.mapWallet.try_emplace(tx->GetHash(), tx, TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/0}, std::nullopt);
    auto& wtx = it->second;

    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());

    // Call GetImmatureCredit() once before adding the key to the wallet to
    // cache the current immature credit amount, which is 0.
    BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE), 0);

    // Invalidate the cached value, add the key, and make sure a new immature
    // credit amount is calculated.
    wtx.MarkDirty();
    AddKey(wallet, coinbaseKey);
    BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE), 50*COIN);
}

static int64_t AddTx(ChainstateManager& chainman, CWallet& wallet, uint32_t lockTime, int64_t mockTime, int64_t blockTime)
{
    CMutableTransaction tx;
    TxState state = TxStateInactive{};
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex* block = nullptr;
    if (blockTime > 0) {
        LOCK(cs_main);
        auto inserted = chainman.BlockIndex().emplace(std::piecewise_construct, std::make_tuple(GetRandHash()), std::make_tuple());
        assert(inserted.second);
        const uint256& hash = inserted.first->first;
        block = &inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
        state = TxStateConfirmed{hash, block->nHeight, /*index=*/0};
    }
    return wallet.AddToWallet(MakeTransactionRef(tx), std::nullopt, state, [&](CWalletTx& wtx, bool /* new_tx */) {
        // Assign wtx.m_state to simplify test and avoid the need to simulate
        // reorg events. Without this, AddToWallet asserts false when the same
        // transaction is confirmed in different blocks.
        wtx.m_state = state;
        return true;
    })->nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart)
{
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 5, 50, 600), 300);
}

BOOST_AUTO_TEST_CASE(LoadReceiveRequests)
{
    CTxDestination dest = PKHash();
    LOCK(m_wallet.cs_wallet);
    WalletBatch batch{m_wallet.GetDatabase()};
    m_wallet.SetAddressUsed(batch, dest, true);
    m_wallet.SetAddressReceiveRequest(batch, dest, "0", "val_rr0");
    m_wallet.SetAddressReceiveRequest(batch, dest, "1", "val_rr1");

    auto values = m_wallet.GetAddressReceiveRequests();
    BOOST_CHECK_EQUAL(values.size(), 2U);
    BOOST_CHECK_EQUAL(values[0], "val_rr0");
    BOOST_CHECK_EQUAL(values[1], "val_rr1");
}

// Test some watch-only LegacyScriptPubKeyMan methods by the procedure of loading (LoadWatchOnly),
// checking (HaveWatchOnly), getting (GetWatchPubKey) and removing (RemoveWatchOnly) a
// given PubKey, resp. its corresponding P2PK Script. Results of the impact on
// the address -> PubKey map is dependent on whether the PubKey is a point on the curve
static void TestWatchOnlyPubKey(LegacyScriptPubKeyMan* spk_man, const CPubKey& add_pubkey)
{
    CScript p2pk = GetScriptForRawPubKey(add_pubkey);
    CKeyID add_address = add_pubkey.GetID();
    CPubKey found_pubkey;
    LOCK(spk_man->cs_KeyStore);

    // all Scripts (i.e. also all PubKeys) are added to the general watch-only set
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));
    spk_man->LoadWatchOnly(p2pk);
    BOOST_CHECK(spk_man->HaveWatchOnly(p2pk));

    // only PubKeys on the curve shall be added to the watch-only address -> PubKey map
    bool is_pubkey_fully_valid = add_pubkey.IsFullyValid();
    if (is_pubkey_fully_valid) {
        BOOST_CHECK(spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey);
    } else {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == CPubKey()); // passed key is unchanged
    }

    spk_man->RemoveWatchOnly(p2pk);
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));

    if (is_pubkey_fully_valid) {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey); // passed key is unchanged
    }
}

// Cryptographically invalidate a PubKey whilst keeping length and first byte
static void PollutePubKey(CPubKey& pubkey)
{
    std::vector<unsigned char> pubkey_raw(pubkey.begin(), pubkey.end());
    std::fill(pubkey_raw.begin()+1, pubkey_raw.end(), 0);
    pubkey = CPubKey(pubkey_raw);
    assert(!pubkey.IsFullyValid());
    assert(pubkey.IsValid());
}

// Test watch-only logic for PubKeys
BOOST_AUTO_TEST_CASE(WatchOnlyPubKeys)
{
    CKey key;
    CPubKey pubkey;
    LegacyScriptPubKeyMan* spk_man = m_wallet.GetOrCreateLegacyScriptPubKeyMan();

    BOOST_CHECK(!spk_man->HaveWatchOnly());

    // uncompressed valid PubKey
    key.MakeNewKey(false);
    pubkey = key.GetPubKey();
    assert(!pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // uncompressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed valid PubKey
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();
    assert(pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // invalid empty PubKey
    pubkey = CPubKey();
    TestWatchOnlyPubKey(spk_man, pubkey);
}

class ListCoinsTestingSetup : public TestChain100Setup
{
public:
    ListCoinsTestingSetup()
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), m_args, coinbaseKey);
    }

    ~ListCoinsTestingSetup()
    {
        wallet.reset();
    }

    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CCoinControl dummy;
        {
            constexpr int RANDOM_CHANGE_POSITION = -1;
            auto res = CreateTransaction(*wallet, {recipient}, RANDOM_CHANGE_POSITION, dummy, std::nullopt, std::nullopt, false);
            BOOST_CHECK(res);
            tx = MakeTransactionRef(res->tx);
        }
        wallet->CommitTransaction(tx, {}, {});
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        LOCK(wallet->cs_wallet);
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(wallet->GetLastBlockHeight() + 1, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
        return it->second;
    }

    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoinsTest, ListCoinsTestingSetup)
{
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<AnyWalletUTXO>> list;
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(50 * COIN, GetAvailableBalance(*wallet));

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{GetScriptForRawPubKey({}), 1 * COIN, false /* subtract fee */});
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoinsListUnspent(*wallet).Size(), 2U);
    }
    for (const auto& group : list) {
        for (const auto& coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(coin.GetID());
        }
    }
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoinsListUnspent(*wallet).Size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK(wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

BOOST_AUTO_TEST_CASE(legacy_mweb_keychain_load_caches_scan_secret)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
    wallet.SetupLegacyScriptPubKeyMan();
    WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_MWEB));

    LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);
    LOCK(spk_man->cs_KeyStore);

    const CPubKey seed = spk_man->GenerateNewSeed();
    spk_man->SetHDSeed(seed);

    CHDChain uncached_chain = spk_man->GetHDChain();
    BOOST_REQUIRE(uncached_chain.mweb_scan_key.has_value());
    uncached_chain.nVersion = CHDChain::VERSION_HD_MWEB;
    uncached_chain.mweb_scan_key.reset();
    uncached_chain.mweb_spend_pubkey.reset();
    spk_man->LoadHDChain(uncached_chain);

    BOOST_CHECK(!spk_man->GetHDChain().mweb_scan_key.has_value());
    spk_man->LoadMWEBKeychain();

    const CHDChain& cached_chain = spk_man->GetHDChain();
    BOOST_CHECK_EQUAL(cached_chain.nVersion, CHDChain::VERSION_HD_MWEB_RECEIVE);
    BOOST_REQUIRE(cached_chain.mweb_scan_key.has_value());
    BOOST_REQUIRE(cached_chain.mweb_spend_pubkey.has_value());
    const std::optional<SecretKey> scan_secret = spk_man->GetScanSecret();
    BOOST_REQUIRE(scan_secret);
    BOOST_CHECK(*scan_secret == *cached_chain.mweb_scan_key);
}

BOOST_AUTO_TEST_CASE(legacy_mweb_ignores_transparent_only_inactive_chain)
{
    struct KeypoolArgGuard {
        KeypoolArgGuard() { gArgs.ForceSetArg("-keypool", "1"); }
        ~KeypoolArgGuard()
        {
            gArgs.LockSettings([](util::Settings& settings) {
                settings.forced_settings.erase("keypool");
            });
        }
    } keypool_arg_guard;

    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
    wallet.SetupLegacyScriptPubKeyMan();
    WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_MWEB));

    LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);

    CPubKey inactive_seed;
    {
        LOCK(spk_man->cs_KeyStore);
        inactive_seed = spk_man->GenerateNewSeed();

        CHDChain inactive_chain;
        inactive_chain.nVersion = CHDChain::VERSION_HD_CHAIN_SPLIT;
        inactive_chain.seed_id = inactive_seed.GetID();

        WalletBatch batch(wallet.GetDatabase());
        spk_man->GenerateNewKey(batch, inactive_chain, KeyPurpose::EXTERNAL);
        spk_man->GenerateNewKey(batch, inactive_chain, KeyPurpose::INTERNAL);
        spk_man->AddInactiveHDChain(inactive_chain);

        const CPubKey active_seed = spk_man->GenerateNewSeed();
        spk_man->SetHDSeed(active_seed);
    }

    BOOST_REQUIRE(spk_man->TopUp(1));
    spk_man->LoadMWEBKeychain();

    BOOST_CHECK(!spk_man->GetScanSecret(inactive_seed.GetID()));
    BOOST_CHECK_EQUAL(spk_man->GetAllScanSecrets().size(), 1U);

    std::optional<MigrationData> migration_data = spk_man->MigrateToDescriptor();
    BOOST_REQUIRE(migration_data.has_value());

    size_t mweb_desc_count{0};
    for (const auto& desc_spkm : migration_data->desc_spkms) {
        const WalletDescriptor desc = desc_spkm->GetWalletDescriptor();
        const std::optional<OutputType> output_type = desc.descriptor->GetOutputType();
        if (output_type && *output_type == OutputType::MWEB) {
            ++mweb_desc_count;
        }
    }

    BOOST_CHECK_EQUAL(mweb_desc_count, 1U);
    BOOST_CHECK(!migration_data->active_mweb_spkm_id.IsNull());
}

BOOST_AUTO_TEST_CASE(legacy_mweb_generated_key_metadata_uses_mweb_index)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
    wallet.SetupLegacyScriptPubKeyMan();
    WITH_LOCK(wallet.cs_wallet, wallet.LoadMinVersion(FEATURE_MWEB));

    LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    BOOST_REQUIRE(spk_man);

    {
        LOCK(spk_man->cs_KeyStore);
        const CPubKey seed = spk_man->GenerateNewSeed();
        spk_man->SetHDSeed(seed);
    }

    util::Result<CTxDestination> dest = spk_man->GetNewDestination(OutputType::MWEB);
    BOOST_REQUIRE(dest);
    BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*dest));

    const StealthAddress& address = std::get<StealthAddress>(*dest);
    LOCK(spk_man->cs_KeyStore);
    const auto metadata_it = spk_man->mapKeyMetadata.find(address.GetSpendPubKey().GetID());
    BOOST_REQUIRE(metadata_it != spk_man->mapKeyMetadata.end());
    BOOST_CHECK(metadata_it->second.key_origin.hdkeypath.path.empty());
    BOOST_REQUIRE(metadata_it->second.key_origin.hdkeypath.mweb_index.has_value());
    const uint32_t mweb_index = *metadata_it->second.key_origin.hdkeypath.mweb_index;
    BOOST_CHECK_EQUAL(metadata_it->second.hdKeypath, "x/" + std::to_string(mweb_index));
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup)
{
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        wallet->SetupLegacyScriptPubKeyMan();
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        BOOST_CHECK(!wallet->TopUpKeyPool(1000));
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    }
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    }
}

// Explicit calculation which is used to test the wallet constant
// We get the same virtual size due to rounding(weight/4) for both use_max_sig values
static size_t CalculateNestedKeyhashInputSize(bool use_max_sig)
{
    // Generate ephemeral valid pubkey
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    uint160 key_hash(Hash160(pubkey));

    // Create inner-script to enter into keystore. Key hash can't be 0...
    CScript inner_script = CScript() << OP_0 << std::vector<unsigned char>(key_hash.begin(), key_hash.end());

    // Create outer P2SH script for the output
    uint160 script_id(Hash160(inner_script));
    CScript script_pubkey = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

    // Add inner-script to key store and key to watchonly
    FillableSigningProvider keystore;
    keystore.AddCScript(inner_script);
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;

    if (!ProduceSignature(keystore, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, script_pubkey, sig_data)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return (size_t)GetVirtualTransactionInputSize(tx_in);
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup)
{
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(false), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(true), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
}

bool malformed_descriptor(std::ios_base::failure e)
{
    std::string s(e.what());
    return s.find("Missing checksum") != std::string::npos;
}

BOOST_FIXTURE_TEST_CASE(wallet_descriptor_test, BasicTestingSetup)
{
    std::vector<unsigned char> malformed_record;
    CVectorWriter vw(0, 0, malformed_record, 0);
    vw << std::string("notadescriptor");
    vw << (uint64_t)0;
    vw << (int32_t)0;
    vw << (int32_t)0;
    vw << (int32_t)1;

    SpanReader vr{0, 0, malformed_record};
    WalletDescriptor w_desc;
    BOOST_CHECK_EXCEPTION(vr >> w_desc, std::ios_base::failure, malformed_descriptor);
}

//! Test CWallet::Create() and its behavior handling potential race
//! conditions if it's called the same time an incoming transaction shows up in
//! the mempool or a new block.
//!
//! It isn't possible to verify there aren't race condition in every case, so
//! this test just checks two specific cases and ensures that timing of
//! notifications in these cases doesn't prevent the wallet from detecting
//! transactions.
//!
//! In the first case, block and mempool transactions are created before the
//! wallet is loaded, but notifications about these transactions are delayed
//! until after it is loaded. The notifications are superfluous in this case, so
//! the test verifies the transactions are detected before they arrive.
//!
//! In the second case, block and mempool transactions are created after the
//! wallet rescan and notifications are immediately synced, to verify the wallet
//! must already have a handler in place for them, and there's no gap after
//! rescanning where new transactions in new blocks could be lost.
BOOST_FIXTURE_TEST_CASE(CreateWallet, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    // Create new wallet with known key and unload it.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);
    CKey key;
    key.MakeNewKey(true);
    AddKey(*wallet, key);
    TestUnloadWallet(std::move(wallet));


    // Add log hook to detect AddToWallet events from rescans, blockConnected,
    // and transactionAddedToMempool notifications
    int addtx_count = 0;
    DebugLogHelper addtx_counter("[default wallet] AddToWallet", [&](const std::string* s) {
        if (s) ++addtx_count;
        return false;
    });


    bool rescan_completed = false;
    DebugLogHelper rescan_check("[default wallet] Rescan completed", [&](const std::string* s) {
        if (s) rescan_completed = true;
        return false;
    });


    // Block the queue to prevent the wallet receiving blockConnected and
    // transactionAddedToMempool notifications, and create block and mempool
    // transactions paying to the wallet
    std::promise<void> promise;
    CallFunctionInValidationInterfaceQueue([&promise] {
        promise.get_future().wait();
    });
    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto mempool_tx = TestSimpleSpend(*m_coinbase_txns[1], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, false, error));


    // Reload wallet and make sure new transactions are detected despite events
    // being blocked
    wallet = TestLoadWallet(context);
    BOOST_CHECK(rescan_completed);
    // AddToWallet events for block_tx and mempool_tx
    BOOST_CHECK_EQUAL(addtx_count, 2);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_tx.GetHash()), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(mempool_tx.GetHash()), 1U);
    }


    // Unblock notification queue and make sure stale blockConnected and
    // transactionAddedToMempool events are processed
    promise.set_value();
    SyncWithValidationInterfaceQueue();
    // AddToWallet events for block_tx and mempool_tx events are counted a
    // second time as the notification queue is processed
    BOOST_CHECK_EQUAL(addtx_count, 4);


    TestUnloadWallet(std::move(wallet));


    // Load wallet again, this time creating new block and mempool transactions
    // paying to the wallet as the wallet finishes loading and syncing the
    // queue so the events have to be handled immediately. Releasing the wallet
    // lock during the sync is a little artificial but is needed to avoid a
    // deadlock during the sync and simulates a new block notification happening
    // as soon as possible.
    addtx_count = 0;
    auto handler = HandleLoadWallet(context, [&](std::unique_ptr<interfaces::Wallet> wallet) {
            BOOST_CHECK(rescan_completed);
            m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            block_tx = TestSimpleSpend(*m_coinbase_txns[2], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            mempool_tx = TestSimpleSpend(*m_coinbase_txns[3], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, false, error));
            SyncWithValidationInterfaceQueue();
        });
    wallet = TestLoadWallet(context);
    BOOST_CHECK_EQUAL(addtx_count, 2);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_tx.GetHash()), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(mempool_tx.GetHash()), 1U);
    }


    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(CreateWalletWithoutChain, BasicTestingSetup)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestLoadWallet(context);
    BOOST_CHECK(wallet);
    UnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(ZapSelectTx, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);
    CKey key;
    key.MakeNewKey(true);
    AddKey(*wallet, key);

    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    SyncWithValidationInterfaceQueue();

    {
        auto block_hash = block_tx.GetHash();
        auto prev_tx = m_coinbase_txns[0];

        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->HasWalletSpend(CWalletTx(prev_tx, TxStateInactive{}, std::nullopt)));
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_hash), 1u);

        std::vector<uint256> vHashIn{ block_hash }, vHashOut;
        BOOST_CHECK_EQUAL(wallet->ZapSelectTx(vHashIn, vHashOut), DBErrors::LOAD_OK);

        BOOST_CHECK(!wallet->HasWalletSpend(CWalletTx(prev_tx, TxStateInactive{}, std::nullopt)));
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_hash), 0u);
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(IsSpentPartialMWEB, TestChain100Setup)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);

    int tip_height;
    uint256 tip_hash;
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        tip_height = m_node.chainman->ActiveChain().Height();
        tip_hash = m_node.chainman->ActiveChain().Tip()->GetBlockHash();
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(tip_height, tip_hash);
    }

    const mw::Hash spent_id = mw::Hash::FromHex("73ee0d7d430d7fdd94fe9ee7f89e7fe9ed6a20f7865d6fdedeb1dd03dd977a0f");
    const uint256 partial_hash = MWEB::WalletTxInfo::Spent(spent_id).GetHash();
    BOOST_REQUIRE(wallet->AddToWallet(
        MakeTransactionRef(),
        std::make_optional(MWEB::WalletTxInfo::Spent(spent_id)),
        TxStateConfirmed{tip_hash, tip_height, TxStateConfirmed::NO_POSITION_IN_BLOCK}
    ));

    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->IsSpent(spent_id));

        CWalletTx* wtx = wallet->GetWalletTx(partial_hash);
        BOOST_REQUIRE(wtx);

        wtx->m_state = TxStateConflicted{tip_hash, tip_height};
        BOOST_CHECK(!wallet->IsSpent(spent_id));

        wtx->m_state = TxStateInactive{};
        BOOST_CHECK(wallet->IsSpent(spent_id));

        wtx->m_state = TxStateInactive{/*abandoned=*/true};
        BOOST_CHECK(!wallet->IsSpent(spent_id));
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(OutputIsChangeUsesPartialMWEBReceiveInfo, TestChain100Setup)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);

    int tip_height;
    uint256 tip_hash;
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        tip_height = m_node.chainman->ActiveChain().Height();
        tip_hash = m_node.chainman->ActiveChain().Tip()->GetBlockHash();
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(tip_height, tip_hash);
    }

    mw::WalletCoin received_wallet_coin;
    received_wallet_coin.amount = 1'000'000;
    received_wallet_coin.output_id = mw::Hash::FromHex("418f6bb03b49b6a0485f20c5e41088d8d0e77ec580c45a216ca2e98c1c4475ee");
    received_wallet_coin.address_index = mw::CHANGE_INDEX;
    const StealthAddress received_address = StealthAddress::Random();
    received_wallet_coin.address = received_address;

    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetMWWallet()->SaveToWallet({received_wallet_coin}));
    }

    const uint256 partial_hash = MWEB::WalletTxInfo::Received(received_wallet_coin.output_id).GetHash();
    BOOST_REQUIRE(wallet->AddToWallet(
        MakeTransactionRef(),
        std::make_optional(MWEB::WalletTxInfo::Received(received_wallet_coin.output_id)),
        TxStateConfirmed{tip_hash, tip_height, TxStateConfirmed::NO_POSITION_IN_BLOCK}
    ));

    {
        LOCK(wallet->cs_wallet);
        const CWalletTx* wtx = wallet->GetWalletTx(partial_hash);
        BOOST_REQUIRE(wtx != nullptr);
        BOOST_REQUIRE(wtx->IsPartialMWEB());
        BOOST_REQUIRE(wtx->GetMWEBReceivedOutputID() != std::nullopt);
        BOOST_CHECK(*wtx->GetMWEBReceivedOutputID() == received_wallet_coin.output_id);

        BOOST_CHECK(wtx->GetTxOutputs().empty());

        const std::vector<AnyOutputID> tx_only_ids = wtx->GetOutputIDs(OutputIdMode::TX_OUTPUTS);
        BOOST_CHECK(tx_only_ids.empty());

        const std::vector<AnyOutputID> wallet_visible_ids = wtx->GetOutputIDs(OutputIdMode::WALLET_OUTPUTS);
        BOOST_REQUIRE_EQUAL(wallet_visible_ids.size(), 1U);
        BOOST_CHECK(wallet_visible_ids[0] == received_wallet_coin.output_id);

        mw::WalletCoin wallet_coin;
        BOOST_REQUIRE(wallet->GetMWEBWalletCoin(received_wallet_coin.output_id, wallet_coin));
        BOOST_CHECK(wallet_coin == received_wallet_coin);
        BOOST_CHECK_EQUAL(wallet->GetValue(*wtx, AnyOutputID{received_wallet_coin.output_id}), received_wallet_coin.amount);
        BOOST_CHECK(wallet->IsMine(AnyOutputID{received_wallet_coin.output_id}) != ISMINE_NO);
        BOOST_CHECK(OutputIsChange(*wallet, *wtx, AnyOutputID{received_wallet_coin.output_id}));

        GenericAddress extracted_address;
        BOOST_REQUIRE(wallet->ExtractOutputAddress(*wtx, AnyOutputID{received_wallet_coin.output_id}, extracted_address));
        BOOST_CHECK(extracted_address == GenericAddress{received_address});
    }

    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(UpgradePartialMWEBReceiveToFullTransaction, TestChain100Setup)
{
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);

    int tip_height;
    uint256 tip_hash;
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        tip_height = m_node.chainman->ActiveChain().Height();
        tip_hash = m_node.chainman->ActiveChain().Tip()->GetBlockHash();
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->SetLastBlockProcessed(tip_height, tip_hash);
    }

    test::Tx full_mweb_tx = test::TxBuilder()
        .AddPeginKernel(5'000'000, 0)
        .AddOutput(2'000'000)
        .AddOutput(3'000'000)
        .Build();

    mw::WalletCoin received_wallet_coin_1;
    received_wallet_coin_1.amount = full_mweb_tx.GetOutputs()[0].GetAmount();
    received_wallet_coin_1.output_id = full_mweb_tx.GetOutputs()[0].GetOutputID();

    mw::WalletCoin received_wallet_coin_2;
    received_wallet_coin_2.amount = full_mweb_tx.GetOutputs()[1].GetAmount();
    received_wallet_coin_2.output_id = full_mweb_tx.GetOutputs()[1].GetOutputID();

    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->GetMWWallet()->SaveToWallet({received_wallet_coin_1, received_wallet_coin_2}));
    }

    const uint256 partial_hash_1 = MWEB::WalletTxInfo::Received(received_wallet_coin_1.output_id).GetHash();
    const uint256 partial_hash_2 = MWEB::WalletTxInfo::Received(received_wallet_coin_2.output_id).GetHash();

    BOOST_REQUIRE(wallet->AddToWallet(
        MakeTransactionRef(),
        std::make_optional(MWEB::WalletTxInfo::Received(received_wallet_coin_1.output_id)),
        TxStateConfirmed{tip_hash, tip_height, TxStateConfirmed::NO_POSITION_IN_BLOCK}
    ));
    BOOST_REQUIRE(wallet->AddToWallet(
        MakeTransactionRef(),
        std::make_optional(MWEB::WalletTxInfo::Received(received_wallet_coin_2.output_id)),
        TxStateConfirmed{tip_hash, tip_height, TxStateConfirmed::NO_POSITION_IN_BLOCK}
    ));

    {
        LOCK(wallet->cs_wallet);
        const CWalletTx* partial_wtx_1 = wallet->GetWalletTx(partial_hash_1);
        const CWalletTx* partial_wtx_2 = wallet->GetWalletTx(partial_hash_2);
        BOOST_REQUIRE(partial_wtx_1 != nullptr);
        BOOST_REQUIRE(partial_wtx_2 != nullptr);
        BOOST_REQUIRE(partial_wtx_1->IsPartialMWEB());
        BOOST_REQUIRE(partial_wtx_2->IsPartialMWEB());
        BOOST_REQUIRE(partial_wtx_1->GetMWEBReceivedOutputID() != std::nullopt);
        BOOST_REQUIRE(partial_wtx_2->GetMWEBReceivedOutputID() != std::nullopt);
        BOOST_REQUIRE(wallet->FindWalletTx(AnyOutputID(received_wallet_coin_1.output_id)) == partial_wtx_1);
        BOOST_REQUIRE(wallet->FindWalletTx(AnyOutputID(received_wallet_coin_2.output_id)) == partial_wtx_2);
    }

    CMutableTransaction full_tx;
    full_tx.mweb_tx = mw::MutableTx::From(*full_mweb_tx.GetTransaction());
    const auto full_tx_ref = MakeTransactionRef(full_tx);
    const uint256 full_hash = full_tx_ref->GetHash();
    BOOST_REQUIRE(full_tx_ref->HasMWEBTx());
    BOOST_REQUIRE(full_tx_ref->HasOutput(AnyOutputID(received_wallet_coin_1.output_id)));
    BOOST_REQUIRE(full_tx_ref->HasOutput(AnyOutputID(received_wallet_coin_2.output_id)));

    BOOST_REQUIRE(wallet->AddToWallet(full_tx_ref, std::nullopt, TxStateInMempool{}));

    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(partial_hash_1), 0U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(partial_hash_2), 0U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(full_hash), 1U);

        const CWalletTx* wtx = wallet->GetWalletTx(full_hash);
        BOOST_REQUIRE(wtx != nullptr);
        BOOST_CHECK(!wtx->IsPartialMWEB());
        BOOST_CHECK(wtx->state<TxStateInMempool>() != nullptr);
    }

    const CWalletTx* from_first_output = wallet->FindWalletTx(AnyOutputID(received_wallet_coin_1.output_id));
    BOOST_REQUIRE(from_first_output != nullptr);
    BOOST_CHECK(from_first_output->GetHash() == full_hash);

    const CWalletTx* from_second_output = wallet->FindWalletTx(AnyOutputID(received_wallet_coin_2.output_id));
    BOOST_REQUIRE(from_second_output != nullptr);
    BOOST_CHECK(from_second_output->GetHash() == full_hash);

    const CWalletTx* from_kernel = wallet->FindWalletTxByKernelId(full_mweb_tx.GetKernels().front().GetKernelID());
    BOOST_REQUIRE(from_kernel != nullptr);
    BOOST_CHECK(from_kernel->GetHash() == full_hash);

    TestUnloadWallet(std::move(wallet));
}

BOOST_AUTO_TEST_CASE(GetMWEBPegoutsReturnsStableComponentIds)
{
    test::Tx mweb_tx = test::TxBuilder()
        .AddPeginKernel(1'000'000, 0)
        .AddPegoutKernel(1'000'000, 0)
        .Build();

    CMutableTransaction tx;
    tx.mweb_tx = mw::MutableTx::From(*mweb_tx.GetTransaction());
    CWalletTx wtx(MakeTransactionRef(tx), TxStateInactive{}, std::nullopt);

    const auto pegouts = wtx.GetMWEBPegouts();
    BOOST_REQUIRE_EQUAL(pegouts.size(), 1U);

    const std::vector<mw::Kernel>& kernels = mweb_tx.GetKernels();
    auto kernel_it = std::find_if(kernels.cbegin(), kernels.cend(), [](const mw::Kernel& kernel) {
        return !kernel.GetPegOuts().empty();
    });
    BOOST_REQUIRE(kernel_it != kernels.cend());

    BOOST_CHECK(pegouts[0].first.kernel_id == kernel_it->GetKernelID());
    BOOST_CHECK_EQUAL(pegouts[0].first.pos, 0U);
    BOOST_CHECK(pegouts[0].second == kernel_it->GetPegOuts()[0]);
}

/** RAII class that provides access to a FailDatabase. Which fails if needed. */
class FailBatch : public DatabaseBatch
{
private:
    bool m_pass{true};
    bool ReadKey(CDataStream&& key, CDataStream& value) override { return m_pass; }
    bool WriteKey(CDataStream&& key, CDataStream&& value, bool overwrite=true) override { return m_pass; }
    bool EraseKey(CDataStream&& key) override { return m_pass; }
    bool HasKey(CDataStream&& key) override { return m_pass; }

public:
    explicit FailBatch(bool pass) : m_pass(pass) {}
    void Flush() override {}
    void Close() override {}

    bool StartCursor() override { return true; }
    bool ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete) override { return false; }
    void CloseCursor() override {}
    bool TxnBegin() override { return false; }
    bool TxnCommit() override { return false; }
    bool TxnAbort() override { return false; }
};

/** A dummy WalletDatabase that does nothing, only fails if needed.**/
class FailDatabase : public WalletDatabase
{
public:
    bool m_pass{true}; // false when this db should fail

    void Open() override {};
    void AddRef() override {}
    void RemoveRef() override {}
    bool Rewrite(const char* pszSkip=nullptr) override { return true; }
    bool Backup(const std::string& strDest) const override { return true; }
    void Close() override {}
    void Flush() override {}
    bool PeriodicFlush() override { return true; }
    void IncrementUpdateCounter() override { ++nUpdateCounter; }
    void ReloadDbEnv() override {}
    std::string Filename() override { return "faildb"; }
    std::string Format() override { return "faildb"; }
    std::unique_ptr<DatabaseBatch> MakeBatch(bool flush_on_close = true) override { return std::make_unique<FailBatch>(m_pass); }
};

enum class FaultPoint {
    NONE,
    WRITE_MINVERSION,
    WRITE_COIN,
    WRITE_TX,
    ERASE_TX,
    COMMIT,
};

using TestDatabaseBytes = std::vector<std::byte>;
using TestDatabaseRecords = std::map<TestDatabaseBytes, TestDatabaseBytes>;

struct FaultDatabaseState
{
    TestDatabaseRecords records;
    std::optional<TestDatabaseRecords> transaction;
    FaultPoint fault{FaultPoint::NONE};
};

class FaultBatch : public DatabaseBatch
{
    std::shared_ptr<FaultDatabaseState> m_state;
    std::optional<TestDatabaseRecords::const_iterator> m_cursor;

    TestDatabaseRecords& Records()
    {
        return m_state->transaction ? *m_state->transaction : m_state->records;
    }

    const TestDatabaseRecords& Records() const
    {
        return m_state->transaction ? *m_state->transaction : m_state->records;
    }

    static std::string KeyType(const TestDatabaseBytes& key)
    {
        CDataStream stream(key, SER_DISK, CLIENT_VERSION);
        std::string type;
        stream >> type;
        return type;
    }

    bool Fail(const FaultPoint point)
    {
        if (m_state->fault != point) {
            return false;
        }

        m_state->fault = FaultPoint::NONE;
        return true;
    }

    bool ReadKey(CDataStream&& key, CDataStream& value) override
    {
        const TestDatabaseBytes key_bytes{key.begin(), key.end()};
        const auto iter = Records().find(key_bytes);
        if (iter == Records().end()) {
            return false;
        }

        value.write(Span<const std::byte>{iter->second.data(), iter->second.size()});
        return true;
    }

    bool WriteKey(CDataStream&& key, CDataStream&& value, bool overwrite = true) override
    {
        const TestDatabaseBytes key_bytes{key.begin(), key.end()};
        const std::string type = KeyType(key_bytes);
        if ((type == DBKeys::MINVERSION && Fail(FaultPoint::WRITE_MINVERSION))
            || (type == DBKeys::COIN && Fail(FaultPoint::WRITE_COIN))
            || (type == DBKeys::TX && Fail(FaultPoint::WRITE_TX))) {
            return false;
        }

        TestDatabaseRecords& records = Records();
        if (!overwrite && records.count(key_bytes) != 0) {
            return false;
        }

        records[key_bytes] = TestDatabaseBytes{value.begin(), value.end()};
        return true;
    }

    bool EraseKey(CDataStream&& key) override
    {
        const TestDatabaseBytes key_bytes{key.begin(), key.end()};
        if (KeyType(key_bytes) == DBKeys::TX && Fail(FaultPoint::ERASE_TX)) {
            return false;
        }

        Records().erase(key_bytes);
        return true;
    }

    bool HasKey(CDataStream&& key) override
    {
        const TestDatabaseBytes key_bytes{key.begin(), key.end()};
        return Records().count(key_bytes) != 0;
    }

public:
    explicit FaultBatch(std::shared_ptr<FaultDatabaseState> state)
        : m_state(std::move(state)) { }

    void Flush() override { }
    void Close() override { }

    bool StartCursor() override
    {
        m_cursor = m_state->records.cbegin();
        return true;
    }

    bool ReadAtCursor(CDataStream& key, CDataStream& value, bool& complete) override
    {
        if (!m_cursor) {
            return false;
        }

        if (*m_cursor == m_state->records.cend()) {
            complete = true;
            return true;
        }

        complete = false;
        key.write(Span<const std::byte>{(*m_cursor)->first.data(), (*m_cursor)->first.size()});
        value.write(Span<const std::byte>{(*m_cursor)->second.data(), (*m_cursor)->second.size()});
        ++(*m_cursor);
        return true;
    }

    void CloseCursor() override { m_cursor.reset(); }

    bool TxnBegin() override
    {
        if (m_state->transaction) {
            return false;
        }

        m_state->transaction = m_state->records;
        return true;
    }

    bool TxnCommit() override
    {
        if (!m_state->transaction || Fail(FaultPoint::COMMIT)) {
            return false;
        }

        m_state->records = std::move(*m_state->transaction);
        m_state->transaction.reset();
        return true;
    }

    bool TxnAbort() override
    {
        if (!m_state->transaction) {
            return false;
        }

        m_state->transaction.reset();
        return true;
    }
};

class FaultDatabase : public WalletDatabase
{
    std::shared_ptr<FaultDatabaseState> m_state;

public:
    explicit FaultDatabase(std::shared_ptr<FaultDatabaseState> state)
        : m_state(std::move(state)) { }

    void Open() override { }
    void AddRef() override { }
    void RemoveRef() override { }
    bool Rewrite(const char* pszSkip = nullptr) override { return true; }
    bool Backup(const std::string& strDest) const override { return true; }
    void Close() override { }
    void Flush() override { }
    bool PeriodicFlush() override { return true; }
    void IncrementUpdateCounter() override { ++nUpdateCounter; }
    void ReloadDbEnv() override { }
    std::string Filename() override { return "faultdb"; }
    std::string Format() override { return "faultdb"; }
    std::unique_ptr<DatabaseBatch> MakeBatch(bool flush_on_close = true) override { return std::make_unique<FaultBatch>(m_state); }
};

/**
 * Checks a wallet invalid state where the inputs (prev-txs) of a new arriving transaction are not marked dirty,
 * while the transaction that spends them exist inside the in-memory wallet tx map (not stored on db due a db write failure).
 */
BOOST_FIXTURE_TEST_CASE(wallet_sync_tx_invalid_state_test, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", m_args, std::make_unique<FailDatabase>());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    // Add tx to wallet
    const auto& op_dest = wallet.GetNewDestination(OutputType::BECH32M, "");
    BOOST_ASSERT(op_dest);

    CMutableTransaction mtx;
    mtx.vout.push_back({COIN, GetScriptForDestination(*op_dest)});
    mtx.vin.push_back(CTxIn(g_insecure_rand_ctx.rand256(), 0));
    const auto& tx_id_to_spend = wallet.AddToWallet(MakeTransactionRef(mtx), std::nullopt, TxStateInMempool{})->GetHash();

    {
        // Cache and verify available balance for the wtx
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx_to_spend = wallet.GetWalletTx(tx_id_to_spend);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx_to_spend), 1 * COIN);
    }

    // Now the good case:
    // 1) Add a transaction that spends the previously created transaction
    // 2) Verify that the available balance of this new tx and the old one is updated (prev tx is marked dirty)

    mtx.vin.clear();
    mtx.vin.push_back(CTxIn(tx_id_to_spend, 0));
    wallet.transactionAddedToMempool(MakeTransactionRef(mtx), 0);
    const uint256& good_tx_id = mtx.GetHash();

    {
        // Verify balance update for the new tx and the old one
        LOCK(wallet.cs_wallet);
        const CWalletTx* new_wtx = wallet.GetWalletTx(good_tx_id);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *new_wtx), 1 * COIN);

        // Now the old wtx
        const CWalletTx* wtx_to_spend = wallet.GetWalletTx(tx_id_to_spend);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx_to_spend), 0 * COIN);
    }

    // Now the bad case:
    // 1) Make db always fail
    // 2) Try to add a transaction that spends the previously created transaction and
    //    verify that we are not moving forward if the wallet cannot store it
    static_cast<FailDatabase&>(wallet.GetDatabase()).m_pass = false;
    mtx.vin.clear();
    mtx.vin.push_back(CTxIn(good_tx_id, 0));
    BOOST_CHECK_EXCEPTION(wallet.transactionAddedToMempool(MakeTransactionRef(mtx), 0),
                          std::runtime_error,
                          HasReason("DB error adding transaction to wallet, write failed"));
}

static const std::string V0215_MWEB_INFO_HEX{
    "01020700008097ca20a34f2dc3a2f78cbb2b3ab34aaf42a34e9c86e6f8dbcd44f9a3f68d5eb3e8be91000000"
};

static void SetV0215PartialMWEBInfo(CWalletTx& wtx)
{
    wtx.mapValue["mweb_info"] = V0215_MWEB_INFO_HEX;
}

static mw::WalletCoin V0215MWEBWalletCoin()
{
    const MWEB::WalletTxInfo info = MWEB::WalletTxInfo::FromHex(V0215_MWEB_INFO_HEX);
    assert(info.legacy_received_coin);
    return *info.legacy_received_coin;
}

BOOST_FIXTURE_TEST_CASE(MWEBWalletDatabaseWriteFailures, TestingSetup)
{
    auto state = std::make_shared<FaultDatabaseState>();
    CWallet wallet(m_node.chain.get(), "", m_args, std::make_unique<FaultDatabase>(state));

    state->fault = FaultPoint::WRITE_MINVERSION;
    BOOST_CHECK(!wallet.SetMinVersion(FEATURE_V24));
    BOOST_CHECK(wallet.GetVersion() < FEATURE_V24);

    const mw::WalletCoin coin = V0215MWEBWalletCoin();
    {
        LOCK(wallet.cs_wallet);
        state->fault = FaultPoint::WRITE_MINVERSION;
        BOOST_CHECK(!wallet.GetMWWallet()->SaveToWallet({coin}));
        BOOST_CHECK(wallet.GetVersion() < FEATURE_V24);

        mw::WalletCoin loaded_coin;
        BOOST_CHECK(!wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));

        state->fault = FaultPoint::WRITE_COIN;
        BOOST_CHECK(!wallet.GetMWWallet()->SaveToWallet({coin}));

        BOOST_CHECK(!wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));
        BOOST_CHECK_EQUAL(wallet.GetVersion(), FEATURE_V24);
        int persisted_min_version{0};
        BOOST_REQUIRE(wallet.GetDatabase().MakeBatch()->Read(DBKeys::MINVERSION, persisted_min_version));
        BOOST_CHECK_EQUAL(persisted_min_version, FEATURE_V24);

        mw::WalletCoin second_coin = coin;
        second_coin.output_id = mw::Hash::FromHex("418f6bb03b49b6a0485f20c5e41088d8d0e77ec580c45a216ca2e98c1c4475ee");
        wallet.GetMWWallet()->StageWalletCoins({
            {coin.output_id, coin},
            {second_coin.output_id, second_coin},
        });

        state->fault = FaultPoint::WRITE_COIN;
        BOOST_CHECK(!wallet.GetMWWallet()->SaveStagedCoinsToWallet({coin.output_id, second_coin.output_id}));
        BOOST_CHECK(!wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));
        BOOST_CHECK(!wallet.GetMWEBWalletCoin(second_coin.output_id, loaded_coin));

        BOOST_REQUIRE(wallet.GetMWWallet()->SaveStagedCoinsToWallet({coin.output_id, second_coin.output_id}));
        BOOST_CHECK(wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));
        BOOST_CHECK(wallet.GetMWEBWalletCoin(second_coin.output_id, loaded_coin));
    }

    auto partial_state = std::make_shared<FaultDatabaseState>();
    CWallet partial_wallet(m_node.chain.get(), "", m_args, std::make_unique<FaultDatabase>(partial_state));
    partial_state->fault = FaultPoint::WRITE_MINVERSION;
    BOOST_CHECK(partial_wallet.AddToWallet(
        MakeTransactionRef(),
        std::make_optional(MWEB::WalletTxInfo::Received(coin.output_id)),
        TxStateInactive{}
    ) == nullptr);

    CWalletTx persisted_wtx(nullptr, TxStateInactive{}, std::nullopt);
    BOOST_CHECK(!partial_wallet.GetDatabase().MakeBatch()->Read(
        std::make_pair(DBKeys::TX, MWEB::WalletTxInfo::Received(coin.output_id).GetHash()),
        persisted_wtx
    ));

    auto rewind_state = std::make_shared<FaultDatabaseState>();
    CWallet rewind_wallet(m_node.chain.get(), "", m_args, std::make_unique<FaultDatabase>(rewind_state));
    rewind_wallet.LoadMinVersion(FEATURE_MWEB);
    rewind_wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    rewind_wallet.SetupDescriptorScriptPubKeyMans();

    FlatSigningProvider provider;
    std::string error;
    CKey descriptor_key;
    descriptor_key.MakeNewKey(true);
    WalletDescriptor desc(Parse("combo(" + EncodeSecret(descriptor_key) + ")", provider, error, false), 0, 0, 1, 1);
    BOOST_REQUIRE(rewind_wallet.AddWalletDescriptor(desc, provider, "", false));

    const util::Result<CTxDestination> dest = rewind_wallet.GetNewDestination(OutputType::MWEB, "");
    BOOST_REQUIRE(dest);
    BOOST_REQUIRE(std::holds_alternative<StealthAddress>(*dest));
    const mw::Output output = test::TxBuilder()
        .AddPeginKernel(1'000'000, 0)
        .AddOutput(1'000'000, SecretKey::Random(), std::get<StealthAddress>(*dest))
        .Build()
        .GetOutputs()
        .front()
        .GetOutput();

    {
        LOCK(rewind_wallet.cs_wallet);
        rewind_state->fault = FaultPoint::WRITE_COIN;
        mw::WalletCoin rewound_coin;
        if (rewind_wallet.GetMWWallet()->RewindOutput(output, rewound_coin)) {
            rewind_wallet.AddToWallet(
                MakeTransactionRef(),
                std::make_optional(MWEB::WalletTxInfo::Received(rewound_coin.output_id)),
                TxStateInactive{}
            );
        }

        BOOST_CHECK(!rewind_wallet.GetMWEBWalletCoin(output.GetOutputID(), rewound_coin));
        BOOST_CHECK(rewind_wallet.mapWallet.empty());
    }
}

BOOST_AUTO_TEST_CASE(MWEBWalletTxInfoSerialization)
{
    const mw::WalletCoin coin = V0215MWEBWalletCoin();

    // v0.21.5.4 received records contain a bool followed by a version-2 coin.
    const MWEB::WalletTxInfo from_legacy = MWEB::WalletTxInfo::FromHex(V0215_MWEB_INFO_HEX);
    BOOST_REQUIRE(from_legacy.received_output_id.has_value());
    BOOST_CHECK(*from_legacy.received_output_id == coin.output_id);
    BOOST_REQUIRE(from_legacy.legacy_received_coin.has_value());
    BOOST_CHECK(*from_legacy.legacy_received_coin == coin);

    // The wtx hash covers only the output ID, so it is stable across formats.
    const MWEB::WalletTxInfo received = MWEB::WalletTxInfo::Received(coin.output_id);
    BOOST_CHECK(from_legacy.GetHash() == received.GetHash());

    // Round-trip of the v24 received format: ID only, no embedded coin.
    const MWEB::WalletTxInfo received_rt = MWEB::WalletTxInfo::FromHex(received.ToHex());
    BOOST_CHECK(received_rt == received);
    BOOST_CHECK(!received_rt.legacy_received_coin.has_value());
    BOOST_CHECK(received_rt.GetHash() == received.GetHash());

    // Re-serializing a parsed legacy record emits the v24 format.
    BOOST_CHECK_EQUAL(from_legacy.ToHex(), received.ToHex());

    // Spent records are byte-identical between the two formats.
    const mw::Hash spent_id = mw::Hash::FromHex("73ee0d7d430d7fdd94fe9ee7f89e7fe9ed6a20f7865d6fdedeb1dd03dd977a0f");
    CDataStream legacy_spent(SER_DISK, PROTOCOL_VERSION);
    legacy_spent << false << spent_id;
    const MWEB::WalletTxInfo spent = MWEB::WalletTxInfo::Spent(spent_id);
    BOOST_CHECK_EQUAL(HexStr(legacy_spent), spent.ToHex());
    const MWEB::WalletTxInfo spent_rt = MWEB::WalletTxInfo::FromHex(spent.ToHex());
    BOOST_CHECK(spent_rt == spent);
    BOOST_CHECK(spent_rt.GetHash() == spent.GetHash());
}

BOOST_FIXTURE_TEST_CASE(MWEBLegacyWalletCoinMigration, TestingSetup)
{
    const mw::WalletCoin coin = V0215MWEBWalletCoin();
    const uint256 old_wtx_hash{coin.output_id.vec()};
    const uint256 new_wtx_hash = MWEB::WalletTxInfo::Received(coin.output_id).GetHash();

    auto database = CreateMockWalletDatabase();
    {
        CWalletTx legacy_wtx(MakeTransactionRef(), TxStateInactive{}, std::nullopt);
        SetV0215PartialMWEBInfo(legacy_wtx);
        std::unique_ptr<DatabaseBatch> batch = database->MakeBatch();
        BOOST_REQUIRE(batch->Write(std::make_pair(DBKeys::TX, old_wtx_hash), legacy_wtx));
    }

    CWallet wallet(m_node.chain.get(), "", m_args, std::move(database));
    BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);

    LOCK(wallet.cs_wallet);

    // Loading in v24 must raise the minversion so older releases fail hard.
    BOOST_CHECK_EQUAL(wallet.GetVersion(), FEATURE_V24);

    // The embedded coin was promoted into the wallet's coin map.
    mw::WalletCoin loaded_coin;
    BOOST_REQUIRE(wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));
    BOOST_CHECK(loaded_coin == coin);

    // The in-memory wtx keeps only the output ID.
    const CWalletTx* wtx = wallet.GetWalletTx(new_wtx_hash);
    BOOST_REQUIRE(wtx != nullptr);
    BOOST_REQUIRE(wtx->mweb_wtx_info.has_value());
    BOOST_CHECK(!wtx->mweb_wtx_info->legacy_received_coin.has_value());
    BOOST_REQUIRE(wtx->mweb_wtx_info->received_output_id.has_value());
    BOOST_CHECK(*wtx->mweb_wtx_info->received_output_id == coin.output_id);

    // The tx record was rewritten in the ID-only format and the coin was
    // persisted as a mweb_coin record.
    CWalletTx reread(nullptr, TxStateInactive{}, std::nullopt);
    std::unique_ptr<DatabaseBatch> batch = wallet.GetDatabase().MakeBatch();
    int persisted_min_version{0};
    BOOST_REQUIRE(batch->Read(DBKeys::MINVERSION, persisted_min_version));
    BOOST_CHECK_EQUAL(persisted_min_version, FEATURE_V24);
    BOOST_CHECK(!batch->Read(std::make_pair(DBKeys::TX, old_wtx_hash), reread));
    BOOST_REQUIRE(batch->Read(std::make_pair(DBKeys::TX, new_wtx_hash), reread));
    BOOST_REQUIRE(reread.mweb_wtx_info.has_value());
    BOOST_CHECK(!reread.mweb_wtx_info->legacy_received_coin.has_value());

    mw::WalletCoin persisted_coin;
    BOOST_REQUIRE(batch->Read(std::make_pair(DBKeys::COIN, coin.output_id), persisted_coin));
    BOOST_CHECK(persisted_coin == coin);
}

BOOST_FIXTURE_TEST_CASE(MWEBLegacyWalletCoinMigrationFailuresAreAtomic, TestingSetup)
{
    const mw::WalletCoin coin = V0215MWEBWalletCoin();
    const uint256 old_wtx_hash{coin.output_id.vec()};
    const uint256 new_wtx_hash = MWEB::WalletTxInfo::Received(coin.output_id).GetHash();

    for (const FaultPoint fault : {
        FaultPoint::WRITE_MINVERSION,
        FaultPoint::WRITE_COIN,
        FaultPoint::WRITE_TX,
        FaultPoint::ERASE_TX,
        FaultPoint::COMMIT,
    }) {
        auto state = std::make_shared<FaultDatabaseState>();
        {
            CWalletTx legacy_wtx(MakeTransactionRef(), TxStateInactive{}, std::nullopt);
            SetV0215PartialMWEBInfo(legacy_wtx);
            FaultDatabase database(state);
            BOOST_REQUIRE(database.MakeBatch()->Write(
                std::make_pair(DBKeys::TX, old_wtx_hash),
                legacy_wtx
            ));
        }

        state->fault = fault;
        {
            CWallet wallet(m_node.chain.get(), "", m_args, std::make_unique<FaultDatabase>(state));
            BOOST_CHECK(wallet.LoadWallet() == DBErrors::NONCRITICAL_ERROR);

            LOCK(wallet.cs_wallet);
            const CWalletTx* wtx = wallet.GetWalletTx(new_wtx_hash);
            BOOST_REQUIRE(wtx != nullptr);
            BOOST_REQUIRE(wtx->mweb_wtx_info);
            BOOST_CHECK(wtx->mweb_wtx_info->legacy_received_coin.has_value());

            mw::WalletCoin loaded_coin;
            BOOST_REQUIRE(wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));
            BOOST_CHECK(loaded_coin == coin);
        }

        {
            FaultDatabase database(state);
            std::unique_ptr<DatabaseBatch> batch = database.MakeBatch();
            CWalletTx persisted_wtx(nullptr, TxStateInactive{}, std::nullopt);
            mw::WalletCoin persisted_coin;
            BOOST_CHECK(batch->Read(std::make_pair(DBKeys::TX, old_wtx_hash), persisted_wtx));
            BOOST_CHECK(!batch->Read(std::make_pair(DBKeys::TX, new_wtx_hash), persisted_wtx));
            BOOST_CHECK(!batch->Read(std::make_pair(DBKeys::COIN, coin.output_id), persisted_coin));
        }

        {
            CWallet wallet(m_node.chain.get(), "", m_args, std::make_unique<FaultDatabase>(state));
            BOOST_REQUIRE(wallet.LoadWallet() == DBErrors::LOAD_OK);

            LOCK(wallet.cs_wallet);
            mw::WalletCoin loaded_coin;
            BOOST_REQUIRE(wallet.GetMWEBWalletCoin(coin.output_id, loaded_coin));
            BOOST_CHECK(loaded_coin == coin);
        }

        FaultDatabase database(state);
        std::unique_ptr<DatabaseBatch> batch = database.MakeBatch();
        CWalletTx persisted_wtx(nullptr, TxStateInactive{}, std::nullopt);
        mw::WalletCoin persisted_coin;
        BOOST_CHECK(!batch->Read(std::make_pair(DBKeys::TX, old_wtx_hash), persisted_wtx));
        BOOST_CHECK(batch->Read(std::make_pair(DBKeys::TX, new_wtx_hash), persisted_wtx));
        BOOST_CHECK(batch->Read(std::make_pair(DBKeys::COIN, coin.output_id), persisted_coin));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
