#pragma once

#include <mw/common/Macros.h>
#include <mw/models/tx/Transaction.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/crypto/Random.h>
#include <mw/crypto/Hasher.h>

#include <test_framework/models/TxInput.h>
#include <test_framework/models/TxOutput.h>

TEST_NAMESPACE

class Tx
{
public:
    Tx(const mw::Transaction::CPtr& pTransaction, const std::vector<TxOutput>& outputs)
        : m_pTransaction(pTransaction), m_outputs(outputs) { }

    static Tx CreatePegIn(const uint64_t amount, const uint64_t fee = 0);

    const mw::Transaction::CPtr& GetTransaction() const noexcept { return m_pTransaction; }
    const std::vector<Kernel>& GetKernels() const noexcept { return m_pTransaction->GetKernels(); }
    const std::vector<TxOutput>& GetOutputs() const noexcept { return m_outputs; }

    const BlindingFactor& GetKernelOffset() const noexcept { return m_pTransaction->GetKernelOffset(); }
    const BlindingFactor& GetOwnerOffset() const noexcept { return m_pTransaction->GetOwnerOffset(); }

    PegInCoin GetPegInCoin() const
    {
        const auto& kernel = m_pTransaction->GetKernels().front();
        return PegInCoin(kernel.GetPegIn(), kernel.GetCommitment());
    }

private:
    mw::Transaction::CPtr m_pTransaction;
    std::vector<TxOutput> m_outputs;
};

END_NAMESPACE