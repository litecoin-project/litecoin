#pragma once

#include <mw/common/Macros.h>
#include <mw/models/block/Header.h>
#include <mw/models/tx/Transaction.h>
#include <mw/consensus/Aggregation.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/LeafSet.h>
#include <mw/mmr/backends/VectorBackend.h>

#include <test_framework/models/MinedBlock.h>
#include <test_framework/models/Tx.h>
#include <test_framework/TestLeafSet.h>

#include <iostream>

TEST_NAMESPACE

class Miner
{
public:
    MinedBlock MineBlock(const uint64_t height, const std::vector<Tx>& txs)
    {
        mw::Transaction::CPtr pTransaction = std::make_shared<const mw::Transaction>();
        if (!txs.empty()) {
            std::vector<mw::Transaction::CPtr> transactions;
            std::transform(
                txs.cbegin(), txs.cend(),
                std::back_inserter(transactions),
                [](const Tx& tx) { return tx.GetTransaction(); }
            );
            pTransaction = Aggregation::Aggregate(transactions);
        }

        auto kernel_offset = pTransaction->GetKernelOffset();
        if (!m_blocks.empty()) {
            kernel_offset = Crypto::AddBlindingFactors({ kernel_offset, m_blocks.back().GetKernelOffset() });
        }

        auto owner_offset = pTransaction->GetOwnerOffset();

        auto kernelMMR = GetKernelMMR(pTransaction->GetKernels());
        auto outputMMR = GetOutputMMR(pTransaction->GetOutputs());
        auto pLeafSet = GetLeafSet(pTransaction->GetInputs(), pTransaction->GetOutputs());

        auto pHeader = std::make_shared<mw::Header>(
            height,
            outputMMR.Root(),
            kernelMMR.Root(),
            pLeafSet->Root(),
            std::move(kernel_offset),
            std::move(owner_offset),
            outputMMR.GetNumLeaves(),
            kernelMMR.GetNumLeaves()
        );

        std::cout << "Mined Block: " << pHeader->GetHeight() << " - " << pHeader->Format() << std::endl;

        MinedBlock minedBlock(
            std::make_shared<mw::Block>(pHeader, pTransaction->GetBody()),
            txs
        );
        m_blocks.push_back(minedBlock);

        return minedBlock;
    }

    void Rewind(const size_t nextHeight)
    {
        m_blocks.erase(m_blocks.begin() + nextHeight, m_blocks.end());
    }

private:
    mmr::MMR GetKernelMMR(const std::vector<Kernel>& additionalKernels = {})
    {
        std::vector<Kernel> kernels;
        for (const auto& block : m_blocks) {
            const auto& blockKernels = block.GetBlock()->GetKernels();
            std::copy(blockKernels.cbegin(), blockKernels.cend(), std::back_inserter(kernels));
        }

        kernels.insert(kernels.end(), additionalKernels.cbegin(), additionalKernels.cend());

        auto mmr = mmr::MMR(std::make_shared<mmr::VectorBackend>());
        for (const Kernel& kernel : kernels) {
            mmr.Add(kernel.Serialized());
        }

        return mmr;
    }

    mmr::MMR GetOutputMMR(const std::vector<Output>& additionalOutputs = {})
    {
        std::vector<Output> outputs;
        for (const auto& block : m_blocks) {
            const auto& blockOutputs = block.GetBlock()->GetOutputs();
            std::copy(blockOutputs.cbegin(), blockOutputs.cend(), std::back_inserter(outputs));
        }

        std::copy(additionalOutputs.cbegin(), additionalOutputs.cend(), std::back_inserter(outputs));

        auto mmr = mmr::MMR(std::make_shared<mmr::VectorBackend>());
        for (const Output& output : outputs) {
            mmr.Add(output.ToOutputId().Serialized());
        }

        return mmr;
    }

    TestLeafSet::Ptr GetLeafSet(const std::vector<Input>& additionalInputs = {}, const std::vector<Output>& additionalOutputs = {})
    {
        std::vector<TestLeafSet::BlockInfo> blockInfos;
        for (const MinedBlock& block : m_blocks) {
            TestLeafSet::BlockInfo blockInfo;
            for (const Input& input : block.GetBlock()->GetInputs()) {
                blockInfo.inputs.push_back(input.GetCommitment());
            }

            for (const Output& output : block.GetBlock()->GetOutputs()) {
                blockInfo.outputs.push_back(output.GetCommitment());
            }

            blockInfos.push_back(blockInfo);
        }

        TestLeafSet::BlockInfo blockInfo;
        for (const Input& input : additionalInputs) {
            blockInfo.inputs.push_back(input.GetCommitment());
        }

        for (const Output& output : additionalOutputs) {
            blockInfo.outputs.push_back(output.GetCommitment());
        }

        blockInfos.push_back(blockInfo);

        return TestLeafSet::Create(blockInfos);
    }

    std::vector<MinedBlock> m_blocks;
};

END_NAMESPACE