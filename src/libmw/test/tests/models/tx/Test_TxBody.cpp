#include <catch.hpp>

#include <test_framework/TxBuilder.h>

TEST_CASE("Tx Body")
{
    const uint64_t pegInAmount = 123;
    const uint64_t fee = 5;

    mw::Transaction::CPtr tx = test::TxBuilder()
        .AddInput(20).AddInput(30, EOutputFeatures::PEGGED_IN)
        .AddOutput(45).AddOutput(pegInAmount, EOutputFeatures::PEGGED_IN)
        .AddPlainKernel(fee).AddPeginKernel(pegInAmount)
        .Build().GetTransaction();

    const TxBody& txBody = tx->GetBody();
    txBody.Validate();

    //
    // Serialization
    //
    Deserializer deserializer(txBody.Serialized());
    REQUIRE(txBody == deserializer.Read<TxBody>());

    //
    // Getters
    //
    REQUIRE(txBody.GetTotalFee() == fee);
}