#include <test_framework/TxBuilder.h>

#include <mw/crypto/Keys.h>

TEST_NAMESPACE

TxBuilder::TxBuilder()
    : m_amount{ 0 }, m_kernelOffset{}, m_stealthOffset{}, m_inputs{}, m_outputs{}, m_kernels{}
{

}

TxBuilder& TxBuilder::AddInput(const TxOutput& input)
{
    return AddInput(input.GetAmount(), SecretKey::Random(), input.GetBlind(), input.GetOutputID());
}

TxBuilder& TxBuilder::AddInput(const CAmount amount)
{
    return AddInput(amount, SecretKey::Random(), BlindingFactor::Random(), SecretKey::Random().GetBigInt());
}

TxBuilder& TxBuilder::AddInput(
    const CAmount amount,
    const SecretKey& privkey,
    const BlindingFactor& blind,
    const mw::Hash& output_id)
{
    m_kernelOffset.Sub(blind);
    m_stealthOffset.Sub(privkey);

    SecretKey input_key = SecretKey::Random();
    m_stealthOffset.Add(input_key);

    Commitment commitment = Commitment::Blinded(blind, amount);
    m_inputs.push_back(mw::Input::Create(output_id, commitment, input_key, privkey));
    m_amount += (int64_t)amount;
    return *this;
}

TxBuilder& TxBuilder::AddOutput(const CAmount amount)
{
    return AddOutput(amount, SecretKey::Random(), StealthAddress::Random());
}

TxBuilder& TxBuilder::AddOutput(
    const CAmount amount,
    const SecretKey& sender_privkey,
    const StealthAddress& receiver_addr)
{
    TxOutput output = TxOutput::Create(sender_privkey, receiver_addr, amount);
    m_kernelOffset.Add(output.GetBlind());
    m_stealthOffset.Add(sender_privkey);

    m_outputs.push_back(std::move(output));
    m_amount -= (int64_t)amount;
    return *this;
}

TxBuilder& TxBuilder::AddPlainKernel(const CAmount fee, const bool add_stealth_excess)
{
    BlindingFactor kernel_excess = BlindingFactor::Random();
    m_kernelOffset.Sub(kernel_excess);

    std::optional<SecretKey> stealth_excess = std::nullopt;
    if (add_stealth_excess) {
        SecretKey offset = SecretKey::Random();
        m_stealthOffset.Sub(offset);
        stealth_excess = std::make_optional(std::move(offset));
    }

    mw::Kernel kernel = mw::Kernel::Create(
        kernel_excess,
        stealth_excess,
        fee,
        std::nullopt,
        std::vector<PegOutCoin>{},
        std::nullopt,
        std::vector<uint8_t>{}
    );

    m_kernels.push_back(std::move(kernel));
    m_amount -= fee;
    return *this;
}

TxBuilder& TxBuilder::AddPeginKernel(const CAmount amount, const std::optional<CAmount>& fee, const bool add_stealth_excess)
{
    BlindingFactor kernel_excess = BlindingFactor::Random();
    m_kernelOffset.Sub(kernel_excess);

    std::optional<SecretKey> stealth_excess = std::nullopt;
    if (add_stealth_excess) {
        stealth_excess = SecretKey::Random();
        m_stealthOffset.Sub(stealth_excess.value());
    }

    mw::Kernel kernel = mw::Kernel::Create(
        kernel_excess,
        stealth_excess,
        fee,
        amount,
        std::vector<PegOutCoin>{},
        std::nullopt,
        std::vector<uint8_t>{}
    );

    m_kernels.push_back(std::move(kernel));
    m_amount += amount;
    return *this;
}

TxBuilder& TxBuilder::AddPegoutKernel(const CAmount amount, const CAmount fee, const bool add_stealth_excess)
{
    BlindingFactor kernel_excess = BlindingFactor::Random();
    m_kernelOffset.Sub(kernel_excess);
    std::vector<uint8_t> ltc_address = SecretKey::Random().vec();

    std::optional<SecretKey> stealth_excess = std::nullopt;
    if (add_stealth_excess) {
        stealth_excess = SecretKey::Random();
        m_stealthOffset.Sub(stealth_excess.value());
    }
    
    PegOutCoin pegout(amount, CScript{ ltc_address.begin(), ltc_address.end() });
    mw::Kernel kernel = mw::Kernel::Create(
        kernel_excess,
        stealth_excess,
        fee,
        std::nullopt,
        std::vector<PegOutCoin>{ pegout },
        std::nullopt,
        std::vector<uint8_t>{}
    );

    m_kernels.push_back(std::move(kernel));
    m_amount -= amount + fee;
    return *this;
}

Tx TxBuilder::Build()
{
    assert(m_amount == 0);

    std::vector<mw::Output> outputs;
    std::transform(
        m_outputs.cbegin(), m_outputs.cend(),
        std::back_inserter(outputs),
        [](const TxOutput& output) { return output.GetOutput(); }
    );

    auto pTransaction = mw::Transaction::Create(
        m_kernelOffset.Total(),
        m_stealthOffset.Total(),
        m_inputs,
        outputs,
        m_kernels
    );
    return Tx{ pTransaction, m_outputs };
}

END_NAMESPACE
