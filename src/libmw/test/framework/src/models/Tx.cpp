#include <test_framework/models/Tx.h>

test::Tx test::Tx::CreatePegIn(const uint64_t amount, const uint64_t fee)
{
    BlindingFactor txOffset = Random::CSPRNG<32>();

    SecretKey sender_privkey = Random::CSPRNG<32>();
    test::TxOutput output = test::TxOutput::Create(
        EOutputFeatures::PEGGED_IN,
        sender_privkey,
        StealthAddress::Random(),
        amount
    );

    BlindingFactor kernelBF = Crypto::AddBlindingFactors({ output.GetBlind() }, { txOffset });
    Kernel kernel = Kernel::Create(kernelBF, fee, amount, boost::none, boost::none);

    auto pTx = mw::Transaction::Create(txOffset, sender_privkey, {}, { output.GetOutput() }, { kernel }, {});
    return Tx{ pTx, { output } };
}