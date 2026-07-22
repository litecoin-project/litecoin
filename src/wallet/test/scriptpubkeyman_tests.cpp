// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <mweb/mweb_models.h>
#include <mw/models/tx/Output.h>
#include <mw/models/tx/Transaction.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(scriptpubkeyman_tests, BasicTestingSetup)

namespace {

PublicKey MalformedPublicKey()
{
    std::array<uint8_t, 33> bytes{};
    bytes[0] = 0x04;
    return PublicKey(bytes.data());
}

Output WithMWEBKeys(const Output& output, const PublicKey& key_exchange, const PublicKey& output_key)
{
    OutputMessage message{
        output.GetFeatures(),
        key_exchange,
        output.GetViewTag(),
        output.GetMaskedValue(),
        output.GetMaskedNonce()
    };

    return Output{
        output.GetCommitment(),
        output.GetSenderPubKey(),
        output_key,
        std::move(message),
        output.GetRangeProof(),
        output.GetSignature()
    };
}

CTransactionRef MWEBTransaction(Output output)
{
    Kernel kernel = Kernel::Create(
        BlindingFactor::Random(),
        boost::none,
        0,
        boost::none,
        std::vector<PegOutCoin>{},
        boost::none
    );

    CMutableTransaction tx;
    tx.mweb_tx = MWEB::Tx{mw::Transaction::Create(
        BlindingFactor::Random(),
        BlindingFactor::Random(),
        std::vector<Input>{},
        std::vector<Output>{std::move(output)},
        std::vector<Kernel>{std::move(kernel)}
    )};
    return MakeTransactionRef(std::move(tx));
}

} // namespace

// Test LegacyScriptPubKeyMan::CanProvide behavior, making sure it returns true
// for recognized scripts even when keys may not be available for signing.
BOOST_AUTO_TEST_CASE(CanProvide)
{
    // Set up wallet and keyman variables.
    NodeContext node;
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateDummyWalletDatabase());
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // Make a 1 of 2 multisig script
    std::vector<CKey> keys(2);
    std::vector<CPubKey> pubkeys;
    for (CKey& key : keys) {
        key.MakeNewKey(true);
        pubkeys.emplace_back(key.GetPubKey());
    }
    CScript multisig_script = GetScriptForMultisig(1, pubkeys);
    CScript p2sh_script = GetScriptForDestination(ScriptHash(multisig_script));
    SignatureData data;

    // Verify the p2sh(multisig) script is not recognized until the multisig
    // script is added to the keystore to make it solvable
    BOOST_CHECK(!keyman.CanProvide(p2sh_script, data));
    keyman.AddCScript(multisig_script);
    BOOST_CHECK(keyman.CanProvide(p2sh_script, data));
}

BOOST_AUTO_TEST_CASE(StealthAddresses)
{
    // Set up wallet and keyman variables.
    NodeContext node;
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateMockWalletDatabase());
    wallet.SetMinVersion(WalletFeature::FEATURE_HD_SPLIT);
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    // Set HD seed
    CKey key = DecodeSecret("6usgJoGKXW12i7Ruxy8Z1C5hrRMVGfLmi9NU9uDQJMPXDJ6tQAH");
    CPubKey seed = keyman.DeriveNewSeed(key);
    keyman.SetHDSeed(seed);
    keyman.TopUp();

    // Check generated MWEB keychain
    mw::Keychain::Ptr mweb_keychain = keyman.GetMWEBKeychain();
    BOOST_CHECK(mweb_keychain != nullptr);
    BOOST_CHECK(mweb_keychain->GetSpendSecret().ToHex() == "2396e5c33b07dfa2d9e70da1dcbdad0ad2399e5672ff2d4afbe3b20bccf3ba1b");
    BOOST_CHECK(mweb_keychain->GetScanSecret().ToHex() == "918271168655385e387907612ee09d755be50c4685528f9f53eabae380ecba97");

    // Check "change" (idx=0) address is USED
    StealthAddress change_address = mweb_keychain->GetStealthAddress(0);
    BOOST_CHECK(EncodeDestination(change_address) == "ltcmweb1qq20e2arnhvxw97katjkmsd35agw3capxjkrkh7dk8d30rczm8ypxuq329nwh2twmchhqn3jqh7ua4ps539f6aazh79jy76urqht4qa59ts3at6gf");
    BOOST_CHECK(keyman.IsMine(change_address) == ISMINE_SPENDABLE);
    BOOST_CHECK(keyman.GetAllReserveKeys().find(change_address.B().GetID()) == keyman.GetAllReserveKeys().end());
    BOOST_CHECK(*keyman.GetMetadata(change_address)->mweb_index == 0);

    // Check "peg-in" (idx=1) address is USED
    StealthAddress pegin_address = mweb_keychain->GetStealthAddress(1);
    BOOST_CHECK(EncodeDestination(pegin_address) == "ltcmweb1qqg5hddkl4uhspjwg9tkmatxa4s6gswdaq9swl8vsg5xxznmye7phcqatzc62mzkg788tsrfcuegxe9q3agf5cplw7ztqdusqf7x3n2tl55x4gvyt");
    BOOST_CHECK(keyman.IsMine(pegin_address) == ISMINE_SPENDABLE);
    BOOST_CHECK(keyman.GetAllReserveKeys().find(pegin_address.B().GetID()) == keyman.GetAllReserveKeys().end());
    BOOST_CHECK(*keyman.GetMetadata(pegin_address)->mweb_index == 1);

    // Check first receive (idx=2) address is UNUSED
    StealthAddress receive_address = mweb_keychain->GetStealthAddress(2);
    BOOST_CHECK(EncodeDestination(receive_address) == "ltcmweb1qq0yq03ewm830ugmkkvrvjmyyeslcpwk8ayd7k27qx63sryy6kx3ksqm3k6jd24ld3r5dp5lzx7rm7uyxfujf8sn7v4nlxeqwrcq6k6xxwqdc6tl3");
    BOOST_CHECK(keyman.IsMine(receive_address) == ISMINE_SPENDABLE);
    BOOST_CHECK(keyman.GetAllReserveKeys().find(receive_address.B().GetID()) != keyman.GetAllReserveKeys().end());
    BOOST_CHECK(*keyman.GetMetadata(receive_address)->mweb_index == 2);

    BOOST_CHECK(keyman.GetHDChain().nMWEBIndexCounter == 1002);
}

BOOST_AUTO_TEST_CASE(MalformedMWEBOutputKeys)
{
    NodeContext node;
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateMockWalletDatabase());
    wallet.SetMinVersion(WalletFeature::FEATURE_HD_SPLIT);
    LegacyScriptPubKeyMan& keyman = *wallet.GetOrCreateLegacyScriptPubKeyMan();

    CKey seed_key = DecodeSecret("6usgJoGKXW12i7Ruxy8Z1C5hrRMVGfLmi9NU9uDQJMPXDJ6tQAH");
    keyman.SetHDSeed(keyman.DeriveNewSeed(seed_key));
    keyman.TopUp();

    mw::Keychain::Ptr mweb_keychain = keyman.GetMWEBKeychain();
    BOOST_REQUIRE(mweb_keychain != nullptr);

    constexpr CAmount amount = 1'234'567;
    Output valid_output = Output::Create(
        nullptr,
        SecretKey::Random(),
        mweb_keychain->GetStealthAddress(2),
        amount
    );

    mw::Coin valid_coin;
    BOOST_REQUIRE(mweb_keychain->RewindOutput(valid_output, valid_coin));
    BOOST_CHECK_EQUAL(valid_coin.address_index, 2);
    BOOST_CHECK_EQUAL(valid_coin.amount, amount);
    BOOST_CHECK(valid_coin.output_id == valid_output.GetOutputID());
    BOOST_CHECK(valid_coin.HasSpendKey());

    const PublicKey malformed_key = MalformedPublicKey();
    const Output malformed_ke = WithMWEBKeys(valid_output, malformed_key, valid_output.Ko());
    const Output malformed_ko = WithMWEBKeys(valid_output, valid_output.Ke(), malformed_key);

    auto check_rewind_failure = [&](const Output& output) {
        mw::Coin coin = valid_coin;
        const std::vector<uint8_t> original_coin = coin.Serialized();
        bool rewound = true;
        BOOST_CHECK_NO_THROW(rewound = mweb_keychain->RewindOutput(output, coin));
        BOOST_CHECK(!rewound);
        BOOST_CHECK(coin.Serialized() == original_coin);
    };

    check_rewind_failure(malformed_ke);
    check_rewind_failure(malformed_ko);

    auto check_callback_ignores_output = [&](const Output& output) {
        const CTransactionRef tx = MWEBTransaction(output);
        size_t wallet_size;
        {
            LOCK(wallet.cs_wallet);
            wallet_size = wallet.mapWallet.size();
        }

        BOOST_CHECK_NO_THROW(wallet.transactionAddedToMempool(tx, 0));

        {
            LOCK(wallet.cs_wallet);
            BOOST_CHECK_EQUAL(wallet.mapWallet.size(), wallet_size);
        }
        mw::Coin stored_coin;
        BOOST_CHECK(!wallet.GetMWWallet()->GetCoin(output.GetOutputID(), stored_coin));
    };

    check_callback_ignores_output(malformed_ke);
    check_callback_ignores_output(malformed_ko);

    const CTransactionRef valid_tx = MWEBTransaction(valid_output);
    BOOST_CHECK_NO_THROW(wallet.transactionAddedToMempool(valid_tx, 0));
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK_EQUAL(wallet.mapWallet.count(valid_tx->GetHash()), 1);
    }

    mw::Coin stored_coin;
    BOOST_REQUIRE(wallet.GetMWWallet()->GetCoin(valid_output.GetOutputID(), stored_coin));
    BOOST_CHECK_EQUAL(stored_coin.address_index, 2);
    BOOST_CHECK_EQUAL(stored_coin.amount, amount);
}

BOOST_AUTO_TEST_SUITE_END()
