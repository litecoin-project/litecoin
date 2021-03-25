#include <catch.hpp>

#include <mw/consensus/Aggregation.h>

#include <test_framework/TxBuilder.h>

TEST_CASE("Aggregation")
{
    mw::Transaction::CPtr tx1 = test::TxBuilder()
        .AddInput(10).AddInput(20)
        .AddOutput(25).AddPlainKernel(5, true)
        .Build().GetTransaction();
    tx1->Validate();

    mw::Transaction::CPtr tx2 = test::TxBuilder()
        .AddInput(20)
        .AddOutput(15).AddPlainKernel(5, true)
        .Build().GetTransaction();
    tx2->Validate();

    mw::Transaction::CPtr pAggregated = Aggregation::Aggregate({ tx1, tx2 });
    pAggregated->Validate();

    std::vector<Input> inputs = tx1->GetInputs();
    inputs.insert(inputs.end(), tx2->GetInputs().begin(), tx2->GetInputs().end());
    std::sort(inputs.begin(), inputs.end(), SortByCommitment);
    REQUIRE(pAggregated->GetInputs().size() == 3);
    REQUIRE(pAggregated->GetInputs() == inputs);

    std::vector<Output> outputs = tx1->GetOutputs();
    outputs.insert(outputs.end(), tx2->GetOutputs().begin(), tx2->GetOutputs().end());
    std::sort(outputs.begin(), outputs.end(), SortByCommitment);
    REQUIRE(pAggregated->GetOutputs().size() == 2);
    REQUIRE(pAggregated->GetOutputs() == outputs);

    std::vector<Kernel> kernels = tx1->GetKernels();
    kernels.insert(kernels.end(), tx2->GetKernels().begin(), tx2->GetKernels().end());
    std::sort(kernels.begin(), kernels.end(), SortByHash);
    REQUIRE(pAggregated->GetKernels().size() == 2);
    REQUIRE(pAggregated->GetKernels() == kernels);

    std::vector<SignedMessage> owner_sigs = tx1->GetOwnerSigs();
    owner_sigs.insert(owner_sigs.end(), tx2->GetOwnerSigs().begin(), tx2->GetOwnerSigs().end());
    std::sort(owner_sigs.begin(), owner_sigs.end(), SortByHash);
    REQUIRE(pAggregated->GetOwnerSigs().size() == 2);
    REQUIRE(pAggregated->GetOwnerSigs() == owner_sigs);

    BlindingFactor kernel_offset = Blinds()
        .Add(tx1->GetKernelOffset())
        .Add(tx2->GetKernelOffset())
        .Total();
    REQUIRE(pAggregated->GetKernelOffset() == kernel_offset);

    BlindingFactor owner_offset = Blinds()
        .Add(tx1->GetOwnerOffset())
        .Add(tx2->GetOwnerOffset())
        .Total();
    REQUIRE(pAggregated->GetOwnerOffset() == owner_offset);
}