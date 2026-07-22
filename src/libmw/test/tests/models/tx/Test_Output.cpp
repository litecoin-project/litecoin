// Copyright (c) 2021 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mw/crypto/Blinds.h>
#include <mw/crypto/Bulletproofs.h>
#include <mw/crypto/Hasher.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/SecretKeys.h>
#include <mw/models/tx/Output.h>
#include <mw/models/wallet/StealthAddress.h>

#include <mweb/mweb_policy.h>
#include <primitives/transaction.h>

#include <test_framework/Deserializer.h>
#include <test_framework/TestMWEB.h>
#include <test_framework/TxBuilder.h>

namespace {

PublicKey MalformedPublicKey(const uint8_t prefix, const uint8_t fill)
{
    std::array<uint8_t, 33> bytes;
    bytes.fill(fill);
    bytes[0] = prefix;
    return PublicKey(bytes.data());
}

Output RebuildOutput(
    const test::TxOutput& original,
    const SecretKey& sender_key,
    PublicKey key_exchange_pubkey,
    PublicKey receiver_pubkey)
{
    const Output& output = original.GetOutput();
    const OutputMessage& original_message = output.GetOutputMessage();
    OutputMessage message{
        original_message.features,
        std::move(key_exchange_pubkey),
        original_message.view_tag,
        original_message.masked_value,
        original_message.masked_nonce
    };

    RangeProof::CPtr p_rangeproof = Bulletproofs::Generate(
        original.GetAmount(),
        SecretKey(original.GetBlind().data()),
        SecretKey::Random(),
        SecretKey::Random(),
        ProofMessage{},
        message.Serialized()
    );

    mw::Hash signature_message = Hasher()
        .Append(output.GetCommitment())
        .Append(output.GetSenderPubKey())
        .Append(receiver_pubkey)
        .Append(message.GetHash())
        .Append(p_rangeproof->GetHash())
        .hash();

    return Output{
        output.GetCommitment(),
        output.GetSenderPubKey(),
        std::move(receiver_pubkey),
        std::move(message),
        p_rangeproof,
        Schnorr::Sign(sender_key.data(), signature_message)
    };
}

mw::Transaction::CPtr ReplaceOutput(const mw::Transaction& transaction, Output output)
{
    return mw::Transaction::Create(
        transaction.GetKernelOffset(),
        transaction.GetStealthOffset(),
        transaction.GetInputs(),
        {std::move(output)},
        transaction.GetKernels()
    );
}

bool IsStandardPolicyTx(const mw::Transaction::CPtr& mweb_transaction, std::string& reason)
{
    CMutableTransaction transaction;
    transaction.mweb_tx = MWEB::Tx{mweb_transaction};
    return MWEB::Policy::IsStandardTx(CTransaction{std::move(transaction)}, reason);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(TestOutput, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(Create)
{
    // Generate receiver master keys
    SecretKey a = SecretKey::Random();
    SecretKey b = SecretKey::Random();

    PublicKey A = PublicKey::From(a);

    // Generate receiver sub-address (i = 10)
    SecretKey b_i = SecretKeys::From(b)
        .Add(SecretKey::FromHash(Hasher().Append(A).Append(10).Append(a).hash()))
        .Total();
    StealthAddress receiver_subaddr(
        PublicKey::From(b_i).Mul(a),
        PublicKey::From(b_i)
    );

    // Build output
    uint64_t amount = 1'234'567;
    BlindingFactor blind;
    SecretKey sender_key = SecretKey::Random();
    Output output = Output::Create(
        &blind,
        sender_key,
        receiver_subaddr,
        amount
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
        BOOST_REQUIRE(Hashed(EHashTag::TAG, output.Ke().Mul(a))[0] == output.GetViewTag());

        // Make sure B belongs to wallet
        SecretKey t = SecretKey::FromHash(Hashed(EHashTag::DERIVE, output.Ke().Mul(a)));
        BOOST_REQUIRE(receiver_subaddr.B() == output.Ko().Div(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, t))));

        BlindingFactor r(SecretKey::FromHash(Hashed(EHashTag::BLIND, t)));
        uint64_t value = output.GetMaskedValue() ^ *((uint64_t*)Hashed(EHashTag::VALUE_MASK, t).data());
        BigInt<16> n = output.GetMaskedNonce() ^ BigInt<16>(Hashed(EHashTag::NONCE_MASK, t).data());

        BOOST_REQUIRE(Commitment::Switch(r, value) == output.GetCommitment());

        // Calculate Carol's sending key 's' and check that s*B ?= Ke
        SecretKey s = SecretKey::FromHash(Hasher(EHashTag::SEND_KEY)
            .Append(receiver_subaddr.A())
            .Append(receiver_subaddr.B())
            .Append(value)
            .Append(n)
            .hash());
        BOOST_REQUIRE(output.Ke() == receiver_subaddr.B().Mul(s));

        // Make sure receiver can generate the spend key
        SecretKey spend_key = SecretKeys::From(b_i)
            .Mul(SecretKey::FromHash(Hashed(EHashTag::OUT_KEY, t)))
            .Total();
        BOOST_REQUIRE(output.GetReceiverPubKey() == PublicKey::From(spend_key));
    }
}

BOOST_AUTO_TEST_CASE(MalformedPublicKeysAreNonstandard)
{
    const CAmount amount = 1'234'567;
    const SecretKey sender_key = SecretKey::Random();
    test::Tx tx = test::TxBuilder()
        .AddInput(amount)
        .AddOutput(amount, sender_key, StealthAddress::Random())
        .AddPlainKernel(0)
        .Build();

    const mw::Transaction::CPtr& standard_tx = tx.GetTransaction();
    const test::TxOutput& original = tx.GetOutputs().front();
    BOOST_REQUIRE_NO_THROW(standard_tx->Validate());
    BOOST_REQUIRE(standard_tx->IsStandard());
    std::string reason;
    BOOST_REQUIRE(IsStandardPolicyTx(standard_tx, reason));

    const PublicKey malformed_ke = MalformedPublicKey(0x04, 0x00);
    BOOST_REQUIRE(!malformed_ke.IsValid());
    mw::Transaction::CPtr malformed_ke_tx = ReplaceOutput(
        *standard_tx,
        RebuildOutput(
            original,
            sender_key,
            malformed_ke,
            original.GetOutput().Ko()
        )
    );
    BOOST_REQUIRE_NO_THROW(malformed_ke_tx->Validate());
    BOOST_REQUIRE(!malformed_ke_tx->GetOutputs().front().IsStandard());
    BOOST_REQUIRE(!malformed_ke_tx->IsStandard());
    reason.clear();
    BOOST_REQUIRE(!IsStandardPolicyTx(malformed_ke_tx, reason));
    BOOST_REQUIRE_EQUAL(reason, "non-standard-mweb-tx");

    const PublicKey malformed_ko = MalformedPublicKey(0x02, 0xff);
    BOOST_REQUIRE(!malformed_ko.IsValid());
    mw::Transaction::CPtr malformed_ko_tx = ReplaceOutput(
        *standard_tx,
        RebuildOutput(
            original,
            sender_key,
            original.GetOutput().Ke(),
            malformed_ko
        )
    );
    BOOST_REQUIRE_NO_THROW(malformed_ko_tx->Validate());
    BOOST_REQUIRE(!malformed_ko_tx->GetOutputs().front().IsStandard());
    BOOST_REQUIRE(!malformed_ko_tx->IsStandard());
    reason.clear();
    BOOST_REQUIRE(!IsStandardPolicyTx(malformed_ko_tx, reason));
    BOOST_REQUIRE_EQUAL(reason, "non-standard-mweb-tx");
}

BOOST_AUTO_TEST_SUITE_END()
