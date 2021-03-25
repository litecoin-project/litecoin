#include <catch.hpp>

#include <mw/consensus/KernelSumValidator.h>

#include <test_framework/TxBuilder.h>

TEST_CASE("Tx Transaction")
{
    const uint64_t pegInAmount = 123;
    const uint64_t fee = 5;

    mw::Transaction::CPtr tx = test::TxBuilder()
        .AddInput(20).AddInput(30, EOutputFeatures::PEGGED_IN)
        .AddOutput(45).AddOutput(pegInAmount, EOutputFeatures::PEGGED_IN)
        .AddPlainKernel(fee).AddPeginKernel(pegInAmount)
        .Build().GetTransaction();

    KernelSumValidator::ValidateForTx(*tx);

    //
    // Serialization
    //
    {
        std::vector<uint8_t> serialized = tx->Serialized();

        Deserializer deserializer(serialized);
        REQUIRE(BlindingFactor::Deserialize(deserializer) == tx->GetKernelOffset());
        REQUIRE(BlindingFactor::Deserialize(deserializer) == tx->GetOwnerOffset());
        REQUIRE(TxBody::Deserialize(deserializer) == tx->GetBody());

        Deserializer deserializer2(serialized);
        REQUIRE(*tx == mw::Transaction::Deserialize(deserializer2));
    }

    //
    // Getters
    //
    {
        REQUIRE(tx->GetTotalFee() == fee);
    }
}