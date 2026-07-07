// Copyright (c) 2012-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <clientversion.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(walletdb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(walletdb_readkeyvalue)
{
    /**
     * When ReadKeyValue() reads from either a "key" or "wkey" it first reads the CDataStream steam into a
     * CPrivKey or CWalletKey respectively and then reads a hash of the pubkey and privkey into a uint256.
     * Wallets from 0.8 or before do not store the pubkey/privkey hash, trying to read the hash from old
     * wallets throws an exception, for backwards compatibility this read is wrapped in a try block to
     * silently fail. The test here makes sure the type of exception thrown from CDataStream::read()
     * matches the type we expect, otherwise we need to update the "key"/"wkey" exception type caught.
     */
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    uint256 dummy;
    BOOST_CHECK_THROW(ssValue >> dummy, std::ios_base::failure);
}

// Test CHDChain serialization
BOOST_AUTO_TEST_CASE(walletdb_chdchain)
{
    static constexpr char CHAIN_HD_BASE_HEX[] = "010000003ae9431cf7eebc5be2410c144dfbafd4d6086bb5e3757f93";
    std::vector<uint8_t> hd_base_bytes = ParseHex(CHAIN_HD_BASE_HEX);
    SpanReader hd_base_stream(SER_DISK, CLIENT_VERSION, hd_base_bytes);
    CHDChain chain_hd_base;
    hd_base_stream >> chain_hd_base;
    BOOST_CHECK_EQUAL(chain_hd_base.nVersion, CHDChain::VERSION_HD_BASE);
    BOOST_CHECK_EQUAL(chain_hd_base.seed_id.GetHex(), "937f75e3b56b08d6d4affb4d140c41e25bbceef7");
    BOOST_CHECK_EQUAL(chain_hd_base.nExternalChainCounter, 474212666);
    BOOST_CHECK_EQUAL(chain_hd_base.nInternalChainCounter, 0);
    BOOST_CHECK_EQUAL(chain_hd_base.nMWEBIndexCounter, 0);
    BOOST_CHECK(!chain_hd_base.mweb_scan_key.has_value());
    BOOST_CHECK(!chain_hd_base.mweb_spend_pubkey.has_value());

    static constexpr char CHAIN_HD_CHAIN_SPLIT_HEX[] = "02000000263202cb669e031886aa10e11527d1cad736be9f40ca3fc5b1bd2122";
    std::vector<uint8_t> hd_split_bytes = ParseHex(CHAIN_HD_CHAIN_SPLIT_HEX);
    SpanReader hd_split_stream(SER_DISK, CLIENT_VERSION, hd_split_bytes);
    CHDChain chain_hd_split;
    hd_split_stream >> chain_hd_split;
    BOOST_CHECK_EQUAL(chain_hd_split.nVersion, CHDChain::VERSION_HD_CHAIN_SPLIT);
    BOOST_CHECK_EQUAL(chain_hd_split.seed_id.GetHex(), "c53fca409fbe36d7cad12715e110aa8618039e66");
    BOOST_CHECK_EQUAL(chain_hd_split.nExternalChainCounter, 3405918758);
    BOOST_CHECK_EQUAL(chain_hd_split.nInternalChainCounter, 572636593);
    BOOST_CHECK_EQUAL(chain_hd_split.nMWEBIndexCounter, 0);
    BOOST_CHECK(!chain_hd_split.mweb_scan_key.has_value());
    BOOST_CHECK(!chain_hd_split.mweb_spend_pubkey.has_value());

    static constexpr char CHAIN_HD_MWEB_HEX[] = "03000000851c7e89441867cb9ed072174ab1ff9e1819c7d58fa9598db651e3abe6b00f1f";
    std::vector<uint8_t> hd_mweb_bytes = ParseHex(CHAIN_HD_MWEB_HEX);
    SpanReader hd_mweb_stream(SER_DISK, CLIENT_VERSION, hd_mweb_bytes);
    CHDChain chain_hd_mweb;
    hd_mweb_stream >> chain_hd_mweb;
    BOOST_CHECK_EQUAL(chain_hd_mweb.nVersion, CHDChain::VERSION_HD_MWEB);
    BOOST_CHECK_EQUAL(chain_hd_mweb.seed_id.GetHex(), "8d59a98fd5c719189effb14a1772d09ecb671844");
    BOOST_CHECK_EQUAL(chain_hd_mweb.nExternalChainCounter, 2306743429);
    BOOST_CHECK_EQUAL(chain_hd_mweb.nInternalChainCounter, 2883801526);
    BOOST_CHECK_EQUAL(chain_hd_mweb.nMWEBIndexCounter, 521122022);
    BOOST_CHECK(!chain_hd_mweb.mweb_scan_key.has_value());
    BOOST_CHECK(!chain_hd_mweb.mweb_spend_pubkey.has_value());

    static constexpr char CHAIN_HD_MWEB_WATCH_HEX[] = "040000003f6e5b6ec9f580b28fc3357e63bb4a08e1f01012b728b34267d8195e8d568d6501369716fe4e1872249b01dacb2f6adc548af262be409514b31e42b7d07517f9a2";
    std::vector<uint8_t> hd_mweb_watch_bytes = ParseHex(CHAIN_HD_MWEB_WATCH_HEX);
    SpanReader hd_mweb_watch_stream(SER_DISK, CLIENT_VERSION, hd_mweb_watch_bytes);
    CHDChain chain_hd_mweb_watch;
    hd_mweb_watch_stream >> chain_hd_mweb_watch;
    BOOST_CHECK_EQUAL(chain_hd_mweb_watch.nVersion, CHDChain::VERSION_HD_MWEB_WATCH);
    BOOST_CHECK_EQUAL(chain_hd_mweb_watch.seed_id.GetHex(), "42b328b71210f0e1084abb637e35c38fb280f5c9");
    BOOST_CHECK_EQUAL(chain_hd_mweb_watch.nExternalChainCounter, 1851485759);
    BOOST_CHECK_EQUAL(chain_hd_mweb_watch.nInternalChainCounter, 1578752103);
    BOOST_CHECK_EQUAL(chain_hd_mweb_watch.nMWEBIndexCounter, 1703761549);
    BOOST_REQUIRE(chain_hd_mweb_watch.mweb_scan_key.has_value());
    BOOST_CHECK_EQUAL(chain_hd_mweb_watch.mweb_scan_key->ToHex(), "369716fe4e1872249b01dacb2f6adc548af262be409514b31e42b7d07517f9a2");
    BOOST_CHECK(!chain_hd_mweb_watch.mweb_spend_pubkey.has_value());

    static constexpr char CHAIN_HD_MWEB_RECEIVE_HEX[] = "05000000c1020ac11c2f37544ac48a1ced24fbc81b53dc3c036bb94d9fd2ee2ada371fb7011d07d4659e1e21852121079affe45bc8b13974ebcdf6d56ca3be2042c29629ed010396c1db4f3b862c98b7143a5f2fea75126ed9ff226746f4cd0b90df778ae08932";
    std::vector<uint8_t> hd_mweb_receive_bytes = ParseHex(CHAIN_HD_MWEB_RECEIVE_HEX);
    SpanReader hd_mweb_receive_stream(SER_DISK, CLIENT_VERSION, hd_mweb_receive_bytes);
    CHDChain chain_hd_mweb_receive;
    hd_mweb_receive_stream >> chain_hd_mweb_receive;
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.nVersion, CHDChain::VERSION_HD_MWEB_RECEIVE);
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.seed_id.GetHex(), "4db96b033cdc531bc8fb24ed1c8ac44a54372f1c");
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.nExternalChainCounter, 3238658753);
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.nInternalChainCounter, 720294559);
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.nMWEBIndexCounter, 3072276442);
    BOOST_REQUIRE(chain_hd_mweb_receive.mweb_scan_key.has_value());
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.mweb_scan_key->ToHex(), "1d07d4659e1e21852121079affe45bc8b13974ebcdf6d56ca3be2042c29629ed");
    BOOST_REQUIRE(chain_hd_mweb_receive.mweb_spend_pubkey.has_value());
    BOOST_CHECK_EQUAL(chain_hd_mweb_receive.mweb_spend_pubkey->ToHex(), "0396c1db4f3b862c98b7143a5f2fea75126ed9ff226746f4cd0b90df778ae08932");
}

// Test CKeyMetadata serialization
BOOST_AUTO_TEST_CASE(walletdb_ckeymetadata)
{
    static constexpr char METADATA_BASIC_HEX[] = "0100000083c1242200000000";
    std::vector<uint8_t> metadata_basic_bytes = ParseHex(METADATA_BASIC_HEX);
    SpanReader metadata_basic_stream(SER_DISK, CLIENT_VERSION, metadata_basic_bytes);
    CKeyMetadata metadata_basic;
    metadata_basic_stream >> metadata_basic;
    BOOST_CHECK_EQUAL(metadata_basic.nVersion, CKeyMetadata::VERSION_BASIC);
    BOOST_CHECK_EQUAL(metadata_basic.nCreateTime, 572834179);
    BOOST_CHECK(metadata_basic.hdKeypath.empty());
    BOOST_CHECK_EQUAL(metadata_basic.hd_seed_id.GetHex(), CKeyID().GetHex());
    BOOST_CHECK(std::equal(std::begin(metadata_basic.key_origin.fingerprint), std::end(metadata_basic.key_origin.fingerprint), std::begin(std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00})));
    BOOST_CHECK(metadata_basic.key_origin.hdkeypath.path.empty());
    BOOST_CHECK(!metadata_basic.key_origin.hdkeypath.mweb_index.has_value());
    BOOST_CHECK(!metadata_basic.has_key_origin);

    static constexpr char METADATA_WITH_HDDATA_HEX[] = "0a000000baef3e5300000000126d2f30272f31272f32313437303836303631e733eb9c0c2ffab4021dd5871ba164bc5b6f2cf2";
    std::vector<uint8_t> metadata_with_hddata_bytes = ParseHex(METADATA_WITH_HDDATA_HEX);
    SpanReader metadata_with_hddata_stream(SER_DISK, CLIENT_VERSION, metadata_with_hddata_bytes);
    CKeyMetadata metadata_with_hddata;
    metadata_with_hddata_stream >> metadata_with_hddata;
    BOOST_CHECK_EQUAL(metadata_with_hddata.nVersion, CKeyMetadata::VERSION_WITH_HDDATA);
    BOOST_CHECK_EQUAL(metadata_with_hddata.nCreateTime, 1396633530);
    BOOST_CHECK_EQUAL(metadata_with_hddata.hdKeypath, "m/0'/1'/2147086061");
    BOOST_CHECK_EQUAL(metadata_with_hddata.hd_seed_id.GetHex(), "f22c6f5bbc64a11b87d51d02b4fa2f0c9ceb33e7");
    BOOST_CHECK(std::equal(std::begin(metadata_with_hddata.key_origin.fingerprint), std::end(metadata_with_hddata.key_origin.fingerprint), std::begin(std::vector<uint8_t>{0x00, 0x00, 0x00, 0x00})));
    BOOST_CHECK(metadata_with_hddata.key_origin.hdkeypath.path.empty());
    BOOST_CHECK(!metadata_with_hddata.key_origin.hdkeypath.mweb_index.has_value());
    BOOST_CHECK(!metadata_with_hddata.has_key_origin);

    static constexpr char METADATA_WITH_KEY_ORIGIN_HEX[] = "0c000000bee5380100000000126d2f30272f31272f3130393535333237302751379303fdd14c2b412ba8e6d7dd141d1514d45f3d5476ed0300000080010000806d5de96301";
    std::vector<uint8_t> metadata_with_key_origin_bytes = ParseHex(METADATA_WITH_KEY_ORIGIN_HEX);
    SpanReader metadata_with_key_origin_stream(SER_DISK, CLIENT_VERSION, metadata_with_key_origin_bytes);
    CKeyMetadata metadata_with_key_origin;
    metadata_with_key_origin_stream >> metadata_with_key_origin;
    BOOST_CHECK_EQUAL(metadata_with_key_origin.nVersion, CKeyMetadata::VERSION_WITH_KEY_ORIGIN);
    BOOST_CHECK_EQUAL(metadata_with_key_origin.nCreateTime, 20506046);
    BOOST_CHECK_EQUAL(metadata_with_key_origin.hdKeypath, "m/0'/1'/109553270'");
    BOOST_CHECK_EQUAL(metadata_with_key_origin.hd_seed_id.GetHex(), "5fd414151d14ddd7e6a82b412b4cd1fd03933751");
    BOOST_CHECK(std::equal(std::begin(metadata_with_key_origin.key_origin.fingerprint), std::end(metadata_with_key_origin.key_origin.fingerprint), std::begin(std::vector<uint8_t>{0x3d, 0x54, 0x76, 0xed})));
    const std::vector<uint32_t> expected = {2147483648, 2147483649, 1676238189};
    BOOST_CHECK_EQUAL_COLLECTIONS(metadata_with_key_origin.key_origin.hdkeypath.path.begin(), metadata_with_key_origin.key_origin.hdkeypath.path.end(), expected.begin(), expected.end());
    BOOST_CHECK(!metadata_with_key_origin.key_origin.hdkeypath.mweb_index.has_value());
    BOOST_CHECK(metadata_with_key_origin.has_key_origin);

    static constexpr char METADATA_WITH_MWEB_HEX[] = "0e0000004711db0600000000146d2f30272f313030272f37353534383535343927b42b9838177bfdd872e14e5a155164db2961b39cffe614810001011407ca6c";
    std::vector<uint8_t> metadata_with_mweb_bytes = ParseHex(METADATA_WITH_MWEB_HEX);
    SpanReader metadata_with_mweb_stream(SER_DISK, CLIENT_VERSION, metadata_with_mweb_bytes);
    CKeyMetadata metadata_with_mweb;
    metadata_with_mweb_stream >> metadata_with_mweb;
    BOOST_CHECK_EQUAL(metadata_with_mweb.nVersion, CKeyMetadata::VERSION_WITH_MWEB_INDEX);
    BOOST_CHECK_EQUAL(metadata_with_mweb.nCreateTime, 115020103);
    BOOST_CHECK_EQUAL(metadata_with_mweb.hdKeypath, "m/0'/100'/755485549'");
    BOOST_CHECK_EQUAL(metadata_with_mweb.hd_seed_id.GetHex(), "9cb36129db6451155a4ee172d8fd7b1738982bb4");
    BOOST_CHECK(std::equal(std::begin(metadata_with_mweb.key_origin.fingerprint), std::end(metadata_with_mweb.key_origin.fingerprint), std::begin(std::vector<uint8_t>{0xff, 0xe6, 0x14, 0x81})));
    BOOST_CHECK(metadata_with_mweb.key_origin.hdkeypath.path.empty());
    BOOST_REQUIRE(metadata_with_mweb.key_origin.hdkeypath.mweb_index.has_value());
    BOOST_CHECK_EQUAL(metadata_with_mweb.key_origin.hdkeypath.mweb_index.value(), 1825179412);
    BOOST_CHECK(metadata_with_mweb.has_key_origin);

}

BOOST_AUTO_TEST_CASE(walletdb_legacy_locked_utxo)
{
    CWallet wallet(m_node.chain.get(), "", m_args, CreateDummyWalletDatabase());
    const COutPoint outpoint{uint256S("0x0111111111111111111111111111111111111111111111111111111111111111"), 3};

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey << DBKeys::LOCKED_UTXO << outpoint;

    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue << uint8_t{'1'};

    std::string str_type;
    std::string str_err;
    BOOST_CHECK(ReadKeyValue(&wallet, ssKey, ssValue, str_type, str_err));
    BOOST_CHECK(str_err.empty());
    BOOST_CHECK_EQUAL(str_type, DBKeys::LOCKED_UTXO);
    BOOST_CHECK(wallet.IsLockedCoin(outpoint));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
