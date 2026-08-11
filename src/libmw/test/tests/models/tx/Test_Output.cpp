// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Blinds.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/KeyDerivation.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>

#include <crypto/common.h>
#include <test_framework/Deserializer.h>
#include <test_framework/TestMWEB.h>

#include <array>

namespace {

PublicKey MalformedPublicKey(const uint8_t prefix, const uint8_t fill)
{
    std::array<uint8_t, 33> bytes;
    bytes.fill(fill);
    bytes[0] = prefix;
    return PublicKey(bytes.data());
}

mw::Output WithPublicKeys(const mw::Output& output, PublicKey key_exchange_pubkey, PublicKey receiver_pubkey)
{
    const mw::OutputStandardFields& fields = *output.GetOutputMessage().standard_fields;
    return mw::Output(
        output.GetCommitment(),
        output.GetSenderPubKey(),
        std::move(receiver_pubkey),
        mw::OutputMessage(
            mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT,
            mw::OutputStandardFields(
                std::move(key_exchange_pubkey),
                fields.view_tag,
                fields.masked_value,
                fields.masked_nonce)),
        output.GetRangeProof(),
        output.GetSignature());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(TestOutput, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(OutputSerialization)
{
    // Create master_scan_secret random output
    std::vector<uint8_t> serialized = ParseHex("09a76a974581c186b808da035e448771aacb731d0c3de241ce3ece1d80cc323748033cf7745ebc41124ea547f3e737084aed0f3f77660a63549769a5826ad0db5284024ae82050afc2f6ba6d539617a5c03e23064d137d4c6cf08d521b36b233fe4113010221242636959cddedf259aa848f3b2c1077f866ba019280b7f660a4deb706cae334c68e58fb05e686bc463f3b0308dd72ea097ac25e7aedf58b775bde42c847b3e0ee1634752cf9b1827549d84edc859c213fa7a63a14d6f6217fd8ca3715ca0b4cbf5e28851dfb4f3d165640460144d6d2b086e4fda9e90c590cb6aa592fc9410f001894e02589f11cd49950959c542d2d7dbeb4ea9d6d6c1ac7af2af839fc1e8bf1d46ff0d8a51367d959b59128aeb8bc01685c6a9f5b11fdfe333f0c7e399642ddd897425d47a58952b11cee2f92bf97a77caa6451da3d6a0793f6e2724c176b7cf798c17e51b6a4c2b9e5c980d5f8cb7a175c8a2d624a9eb63f2f3adedd1343885841716c2a6b05204f2b530c7d19e43feddac9dd4d27b30bc26babec8ccb0b018aa31aacf73c0ce49d2e7e1e6b52cc8892869e8e46874888e6880f8fdfd211f5f8c48f41b6d6a8892f1fc99c83c706fedd42caa62f173e9c931fb86b99c2ea8bfd3c69cc3591ea087ccd8ead7bc162a599388c264a4d3b720d039c34c53ab46b95f3afbe2094fe3d5559f8f2dc1ba50a1112ac019055deedf100a60bc4f4f59ec7c7134661798c3b32d231b92b6ec5ea9949395747d53e8fa5cc134a3708a34e007fcaa60c98e7904ecd30eb8446bc3fb447d7c1ffe104867defd1f248074924da71a0516205c95fb8f3de5dca60dfcccaee88f597e3162c6339acbd682edea94f603b918be2f4ad1c55fa5a7fac538ec4501df180f5bf1fe965aed9585ff2810d82098a4708ff8a556240c901845e1bf5f64563ec2c15def29c32122277871e391977970827647158775e525ec9eeec862618906f9590bf4636651f9f3385cb914f96cd9d31f7987714122251d5b63f7433a1962700b88cbc7f22b2f4e6d4fd50b0c38cac707de59fdd83cde144dff24c0ad6ea68be1420c54218aaeabbcd9f95a0ea79a7a8c888b4d4cbba50f74bb6d8b6ab02e4fdbe72f0e02676453e1bb07ff49ebf4676e2ecc03da287dcd7abd2d0a4ddbd4f1af3c1a224deff201bf53d37cc4ff8a56dc0cdc0a5ac4f27a196990373d19ae095472e02334b129967e4ee7e386998eee2a2ff4809e032d6077f54d98811d4a80ea0526e37");
    mw::Output output = mw::Output::Deserialize(serialized);

    // Serialize the output
    mw::Hash output_id = output.GetOutputID();

    // Verify that the original and deserialized outputs are equal
    BOOST_REQUIRE_EQUAL(output_id.ToHex(), "328b4e83b3e72d85e480bf15b880d73f1dbe88942460220a27b387ffaad8deee");
}

BOOST_AUTO_TEST_CASE(Create)
{
    // Generate receiver master keys
    SecretKey master_scan_secret = SecretKey::Random();
    SecretKey master_spend_secret = SecretKey::Random();

    PublicKey A = PublicKey::From(master_scan_secret);

    // Generate receiver sub-address (i = 10)
    SecretKey b_i = SecretKeys::From(master_spend_secret)
        .Add(Hasher().Append(A).Append(10).Append(master_scan_secret).hash())
        .Total();
    StealthAddress receiver_subaddr(
        PublicKey::From(b_i).Mul(master_scan_secret),
        PublicKey::From(b_i)
    );

    // Build output
    uint64_t amount = 1'234'567;
    BlindingFactor blind;
    SecretKey sender_key = SecretKey::Random();
    mw::Output output = mw::Output::Create(
        &blind,
        sender_key,
        SecretKey::Random(),
        receiver_subaddr,
        amount,
        std::vector<uint8_t>{}
    );
    Commitment expected_commit = Commitment::Switch(blind, amount);

    // Verify bulletproof
    ProofData proof_data = output.BuildProofData();
    BOOST_REQUIRE(proof_data.commitment == expected_commit);
    BOOST_REQUIRE(proof_data.pRangeProof == output.GetRangeProof());
    BOOST_REQUIRE(Bulletproofs::BatchVerify({ output.BuildProofData() }));

    // Verify sender signature
    SignedMessage signed_msg = output.BuildSignedMsg();
    BOOST_REQUIRE(signed_msg.GetPublicKey() == PublicKey::From(sender_key));
    BOOST_REQUIRE(Schnorr::BatchVerify({ signed_msg }));

    // Verify Output ID
    mw::Hash expected_id = Hasher()
        .Append(output.GetCommitment())
        .Append(output.GetSenderPubKey())
        .Append(output.GetReceiverPubKey())
        .Append(output.GetOutputMessage().GetHash())
        .Append(output.GetRangeProof()->GetHash())
        .Append(output.GetSignature())
        .hash();
    BOOST_REQUIRE(output.GetOutputID() == expected_id);

    // Getters
    BOOST_REQUIRE(output.GetCommitment() == expected_commit);

    //
    // Test Restoring Output
    //
    {
        // Check view tag
        BOOST_REQUIRE(Hashed(EHashTag::TAG, output.Ke().Mul(master_scan_secret))[0] == output.GetViewTag());

        // Make sure B belongs to wallet
        SecretKey t = mw::RecoverSharedSecret(output.Ke(), master_scan_secret);
        BOOST_REQUIRE(receiver_subaddr == mw::RecoverSubaddress(output.Ko(), t, master_scan_secret));

        BlindingFactor r = mw::DeriveOutputRawBlind(t);
        const mw::Hash value_mask_hash = Hashed(EHashTag::VALUE_MASK, t);
        uint64_t value = output.GetMaskedValue() ^ ReadLE64(value_mask_hash.data());
        BigInt<16> n = output.GetMaskedNonce() ^ BigInt<16>(Hashed(EHashTag::NONCE_MASK, t).data());

        BOOST_REQUIRE(Commitment::Switch(r, value) == output.GetCommitment());

        // Calculate Carol's sending key 's' and check that s*B ?= Ke
        SecretKey s = mw::DeriveOutputSendKey(receiver_subaddr, value, n);
        BOOST_REQUIRE(output.Ke() == receiver_subaddr.B().Mul(s));

        // Make sure receiver can generate the spend key
        SecretKey spend_key = mw::DeriveOutputSpendKey(b_i, t);
        BOOST_REQUIRE(output.GetReceiverPubKey() == PublicKey::From(spend_key));
    }
}

BOOST_AUTO_TEST_CASE(MalformedPublicKeysAreNonstandard)
{
    const SecretKey scan_secret = SecretKey::Random();
    const SecretKey spend_secret = SecretKey::Random();
    const StealthAddress address(
        PublicKey::From(spend_secret).Mul(scan_secret),
        PublicKey::From(spend_secret));
    const mw::Output output = mw::Output::Create(
        nullptr,
        SecretKey::Random(),
        scan_secret,
        address,
        1'234'567,
        {});

    BOOST_REQUIRE(output.IsStandard());

    const PublicKey malformed_ke = MalformedPublicKey(0x04, 0x00);
    BOOST_REQUIRE(!malformed_ke.IsValid());
    BOOST_REQUIRE(!WithPublicKeys(output, malformed_ke, output.Ko()).IsStandard());

    const PublicKey malformed_ko = MalformedPublicKey(0x02, 0xff);
    BOOST_REQUIRE(!malformed_ko.IsValid());
    BOOST_REQUIRE(!WithPublicKeys(output, output.Ke(), malformed_ko).IsStandard());
}

BOOST_AUTO_TEST_SUITE_END()
