#include <catch.hpp>

#include <mw/consensus/Weight.h>

TEST_CASE("Weight::ExceedsMaximum")
{
    std::vector<Input> inputs;
    std::vector<Output> outputs;
    std::vector<Kernel> kernels;
    std::vector<SignedMessage> sigs;

    for (int i = 0; i < 1000; i++) {
        inputs.push_back(Input());
        kernels.push_back(Kernel());
        outputs.push_back(Output());
        sigs.push_back(SignedMessage());
    }
    TxBody tx1(inputs, outputs, kernels, sigs);

    // 1,000 outputs - 1,000 kernels - 1,000 owner_sigs = 21,000 Weight
    REQUIRE(Weight::Calculate(tx1) == 21'000);
    REQUIRE_FALSE(Weight::ExceedsMaximum(tx1));

    // 1,000 outputs - 1,001 kernels - 1,000 owner_sigs = 21,002 Weight
    inputs.push_back(Input());
    kernels.push_back(Kernel());
    TxBody tx2(inputs, outputs, kernels, sigs);
    REQUIRE(Weight::Calculate(tx2) == 21'002);
    REQUIRE(Weight::ExceedsMaximum(tx2));
}