#include <catch.hpp>

#include <mw/crypto/Crypto.h>
#include <mw/crypto/Schnorr.h>
#include <mw/crypto/Random.h>
#include <mw/models/tx/Kernel.h>

//TEST_CASE("Plain Kernel")
//{
//    uint64_t fee = 1000;
//    BlindingFactor excess_blind(Random::CSPRNG<32>());
//    Kernel kernel = Kernel::CreatePlain(excess_blind, fee);
//
//    //
//    // Serialization
//    //
//    {
//        std::vector<uint8_t> serialized = kernel.Serialized();
//
//        Deserializer deserializer(serialized);
//        REQUIRE(deserializer.Read<uint8_t>() == 0);
//        REQUIRE(deserializer.Read<uint64_t>() == fee);
//        REQUIRE(Commitment::Deserialize(deserializer) == kernel.GetExcess());
//        REQUIRE(Signature::Deserialize(deserializer) == kernel.GetSignature());
//
//        Deserializer deserializer2(serialized);
//        REQUIRE(kernel == Kernel::Deserialize(deserializer2));
//    }
//
//    //
//    // Signature Message
//    //
//    {
//        mw::Hash hashed = kernel.GetSignatureMessage();
//        mw::Hash message_hash = Hasher()
//            .Append<uint8_t>(0)
//            .Append<uint64_t>(fee)
//            .hash();
//        REQUIRE(hashed == message_hash);
//    }
//
//    //
//    // Getters
//    //
//    {
//        REQUIRE(!kernel.IsPegIn());
//        REQUIRE(!kernel.IsPegOut());
//        REQUIRE(kernel.GetPeggedIn() == 0);
//        REQUIRE(kernel.GetPeggedOut() == 0);
//        REQUIRE(kernel.GetLockHeight() == 0);
//        REQUIRE(kernel.GetFee() == fee);
//        REQUIRE(kernel.GetCommitment() == Crypto::CommitBlinded(0, excess_blind));
//        REQUIRE(kernel.GetSignature() == Schnorr::Sign(excess_blind.data(), kernel.GetSignatureMessage()));
//    }
//}
//
//TEST_CASE("Peg-In Kernel")
//{
//    uint64_t amount = 50;
//    BlindingFactor excess_blind(Random::CSPRNG<32>());
//    Kernel kernel = Kernel::CreatePegIn(excess_blind, amount);
//
//    //
//    // Serialization
//    //
//    {
//        std::vector<uint8_t> serialized = kernel.Serialized();
//
//        Deserializer deserializer(serialized);
//        REQUIRE(deserializer.Read<uint8_t>() == 1);
//        REQUIRE(deserializer.Read<uint64_t>() == amount);
//        REQUIRE(Commitment::Deserialize(deserializer) == kernel.GetExcess());
//        REQUIRE(Signature::Deserialize(deserializer) == kernel.GetSignature());
//
//        Deserializer deserializer2(serialized);
//        REQUIRE(kernel == Kernel::Deserialize(deserializer2));
//    }
//
//    //
//    // Signature Message
//    //
//    {
//        mw::Hash hashed = kernel.GetSignatureMessage();
//        mw::Hash message_hash = Hasher()
//            .Append<uint8_t>(1)
//            .Append<uint64_t>(amount)
//            .hash();
//        REQUIRE(hashed == message_hash);
//    }
//
//    //
//    // Getters
//    //
//    {
//        REQUIRE(kernel.IsPegIn());
//        REQUIRE(!kernel.IsPegOut());
//        REQUIRE(kernel.GetPeggedIn() == amount);
//        REQUIRE(kernel.GetPeggedOut() == 0);
//        REQUIRE(kernel.GetLockHeight() == 0);
//        REQUIRE(kernel.GetFee() == 0);
//        REQUIRE(kernel.GetCommitment() == Crypto::CommitBlinded(0, excess_blind));
//        REQUIRE(kernel.GetSignature() == Schnorr::Sign(excess_blind.data(), kernel.GetSignatureMessage()));
//    }
//}
//
//TEST_CASE("Peg-Out Kernel")
//{
//    uint64_t amount = 50;
//    uint64_t fee = 1000;
//    BlindingFactor excess_blind(Random::CSPRNG<32>());
//    Bech32Address address = Bech32Address::FromString("bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9");
//    Kernel kernel = Kernel::CreatePegOut(excess_blind, amount, fee, address);
//
//    //
//    // Serialization
//    //
//    {
//        std::vector<uint8_t> serialized = kernel.Serialized();
//
//        Deserializer deserializer(serialized);
//        REQUIRE(deserializer.Read<uint8_t>() == 2);
//        REQUIRE(deserializer.Read<uint64_t>() == fee);
//        REQUIRE(deserializer.Read<uint64_t>() == amount);
//        REQUIRE(Bech32Address::Deserialize(deserializer) == address);
//        REQUIRE(Commitment::Deserialize(deserializer) == kernel.GetExcess());
//        REQUIRE(Signature::Deserialize(deserializer) == kernel.GetSignature());
//
//        Deserializer deserializer2(serialized);
//        REQUIRE(kernel == Kernel::Deserialize(deserializer2));
//    }
//
//    //
//    // Signature Message
//    //
//    {
//        mw::Hash hashed = kernel.GetSignatureMessage();
//        mw::Hash message_hash = Hasher()
//            .Append<uint8_t>(2)
//            .Append<uint64_t>(fee)
//            .Append<uint64_t>(amount)
//            .Append(address)
//            .hash();
//        REQUIRE(hashed == message_hash);
//    }
//
//    //
//    // Getters
//    //
//    {
//        REQUIRE(!kernel.IsPegIn());
//        REQUIRE(kernel.IsPegOut());
//        REQUIRE(kernel.GetPeggedIn() == 0);
//        REQUIRE(kernel.GetPeggedOut() == amount);
//        REQUIRE(kernel.GetLockHeight() == 0);
//        REQUIRE(kernel.GetFee() == fee);
//        REQUIRE(kernel.GetCommitment() == Crypto::CommitBlinded(0, excess_blind));
//        REQUIRE(kernel.GetSignature() == Schnorr::Sign(excess_blind.data(), kernel.GetSignatureMessage()));
//    }
//}
//
//TEST_CASE("Height-Locked")
//{
//    uint64_t fee = 1000;
//    uint64_t lockHeight = 2500;
//    BlindingFactor excess_blind(Random::CSPRNG<32>());
//    Kernel kernel = Kernel::CreateHeightLocked(excess_blind, fee, lockHeight);
//
//    //
//    // Serialization
//    //
//    {
//        std::vector<uint8_t> serialized = kernel.Serialized();
//
//        Deserializer deserializer(serialized);
//        REQUIRE(deserializer.Read<uint8_t>() == 3);
//        REQUIRE(deserializer.Read<uint64_t>() == fee);
//        REQUIRE(deserializer.Read<uint64_t>() == lockHeight);
//        REQUIRE(Commitment::Deserialize(deserializer) == kernel.GetExcess());
//        REQUIRE(Signature::Deserialize(deserializer) == kernel.GetSignature());
//
//        Deserializer deserializer2(serialized);
//        REQUIRE(kernel == Kernel::Deserialize(deserializer2));
//    }
//
//    //
//    // Signature Message
//    //
//    {
//        mw::Hash hashed = kernel.GetSignatureMessage();
//        mw::Hash message_hash = Hasher()
//            .Append<uint8_t>(3)
//            .Append<uint64_t>(fee)
//            .Append<uint64_t>(lockHeight)
//            .hash();
//        REQUIRE(hashed == message_hash);
//    }
//
//    //
//    // Getters
//    //
//    {
//        REQUIRE(!kernel.HasPegIn());
//        REQUIRE(!kernel.HasPegOut());
//        REQUIRE(kernel.GetPegIn() == 0);
//        REQUIRE(!kernel.GetPegOut().has_value());
//        REQUIRE(kernel.GetLockHeight() == lockHeight);
//        REQUIRE(kernel.GetFee() == fee);
//        REQUIRE(kernel.GetCommitment() == Crypto::CommitBlinded(0, excess_blind));
//        REQUIRE(kernel.GetSignature() == Schnorr::Sign(excess_blind.data(), kernel.GetSignatureMessage()));
//    }
//}
//
//TEST_CASE("Unknown Kernel")
//{
//    uint8_t features = 99;
//    uint64_t fee = 1000;
//    BlindingFactor excess_blind(Random::CSPRNG<32>());
//    std::vector<uint8_t> extraData = { 1, 2, 3 };
//
//    Commitment excess_commit = Crypto::CommitBlinded(0, excess_blind);
//    mw::Hash message_hash = Hasher()
//        .Append<uint8_t>(features)
//        .Append<uint64_t>(fee)
//        .Append(extraData)
//        .hash();
//    Signature sig = Schnorr::Sign(excess_blind.data(), message_hash);
//
//    Kernel kernel(
//        features,     // Unknown type
//        fee,
//        0,
//        0,
//        boost::none,
//        std::vector<uint8_t>(extraData),
//        std::move(excess_commit),
//        std::move(sig)
//    );
//
//    //
//    // Serialization
//    //
//    {
//        std::vector<uint8_t> serialized = kernel.Serialized();
//
//        Deserializer deserializer(serialized);
//        REQUIRE(deserializer.Read<uint8_t>() == features);
//        REQUIRE(deserializer.Read<uint64_t>() == fee);
//        REQUIRE(deserializer.Read<uint8_t>() == extraData.size());
//        REQUIRE(deserializer.ReadVector(extraData.size()) == extraData);
//        REQUIRE(Commitment::Deserialize(deserializer) == kernel.GetExcess());
//        REQUIRE(Signature::Deserialize(deserializer) == kernel.GetSignature());
//
//        Deserializer deserializer2(serialized);
//        REQUIRE(kernel == Kernel::Deserialize(deserializer2));
//    }
//
//    //
//    // Getters
//    //
//    {
//        REQUIRE(!kernel.IsPegIn());
//        REQUIRE(!kernel.IsPegOut());
//        REQUIRE(kernel.GetPeggedIn() == 0);
//        REQUIRE(kernel.GetPeggedOut() == 0);
//        REQUIRE(kernel.GetLockHeight() == 0);
//        REQUIRE(kernel.GetFee() == fee);
//        REQUIRE(kernel.GetCommitment() == Crypto::CommitBlinded(0, excess_blind));
//        REQUIRE(kernel.GetSignature() == Schnorr::Sign(excess_blind.data(), kernel.GetSignatureMessage()));
//        REQUIRE(kernel.GetExtraData() == extraData);
//        REQUIRE(kernel.GetSignatureMessage() == message_hash);
//    }
//}