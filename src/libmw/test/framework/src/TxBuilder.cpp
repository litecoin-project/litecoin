#include <test_framework/TxBuilder.h>

#include <mw/crypto/Keys.h>

TEST_NAMESPACE

TxBuilder::TxBuilder()
    : m_amount{ 0 }, m_kernelOffset{}, m_ownerOffset{}, m_inputs{}, m_outputs{}, m_kernels{}
{

}

TxBuilder& TxBuilder::AddInput(const TxOutput& input)
{
    return AddInput(input.GetAmount(), input.GetFeatures(), input.GetBlindingFactor());
}

TxBuilder& TxBuilder::AddInput(const uint64_t amount, const Features& features, const BlindingFactor& blind)
{
    return AddInput(amount, Random::CSPRNG<32>(), features, blind);
}

TxBuilder& TxBuilder::AddInput(
    const uint64_t amount,
    const SecretKey& privkey,
    const Features& features,
    const BlindingFactor& blind)
{
    m_kernelOffset.Sub(blind);
    m_ownerOffset.Sub(privkey);

    Commitment commitment = Crypto::CommitBlinded(amount, blind);
    PublicKey pubkey = Crypto::CalculatePublicKey(privkey.GetBigInt());
    Signature sig = Schnorr::Sign(privkey.data(), InputMessage());
    m_inputs.push_back(Input{ std::move(commitment), std::move(pubkey), std::move(sig) });
    m_amount += (int64_t)amount;
    return *this;
}

TxBuilder& TxBuilder::AddOutput(const uint64_t amount, const Features& features)
{
    return AddOutput(amount, Random::CSPRNG<32>(), StealthAddress::Random(), features);
}

TxBuilder& TxBuilder::AddOutput(
    const uint64_t amount,
    const SecretKey& sender_privkey,
    const StealthAddress& receiver_addr,
    const Features& features)
{
    TxOutput output = TxOutput::Create(features, sender_privkey, receiver_addr, amount);
    m_kernelOffset.Add(output.GetBlind());
    m_ownerOffset.Add(sender_privkey);

    m_outputs.push_back(std::move(output));
    m_amount -= (int64_t)amount;
    return *this;
}

TxBuilder& TxBuilder::AddPlainKernel(const uint64_t fee, const bool add_owner_sig)
{
    SecretKey kernel_excess = Random::CSPRNG<32>();
    m_kernelOffset.Sub(kernel_excess);

    Kernel kernel = Kernel::Create(kernel_excess, fee, boost::none, boost::none, boost::none);

    if (add_owner_sig) {
        SecretKey offset = Random::CSPRNG<32>();
        m_ownerOffset.Sub(offset);

        mw::Hash msg_hash = kernel.GetHash();
        Signature sig = Schnorr::Sign(offset.data(), msg_hash);
        m_ownerSigs.push_back(SignedMessage{ msg_hash,  Keys::From(offset).PubKey(), sig });
    }

    m_kernels.push_back(std::move(kernel));
    m_amount -= (int64_t)fee;
    return *this;
}

TxBuilder& TxBuilder::AddPeginKernel(const uint64_t amount, const boost::optional<uint64_t>& fee, const bool add_owner_sig)
{
    SecretKey kernel_excess = Random::CSPRNG<32>();
    m_kernelOffset.Sub(kernel_excess);

    Kernel kernel = Kernel::Create(kernel_excess, fee, amount, boost::none, boost::none);

    if (add_owner_sig) {
        SecretKey offset = Random::CSPRNG<32>();
        m_ownerOffset.Sub(offset);

        mw::Hash msg_hash = kernel.GetHash();
        Signature sig = Schnorr::Sign(offset.data(), msg_hash);
        m_ownerSigs.push_back(SignedMessage{ msg_hash,  Keys::From(offset).PubKey(), sig });
    }

    m_kernels.push_back(std::move(kernel));
    m_amount += amount;
    return *this;
}

TxBuilder& TxBuilder::AddPegoutKernel(const uint64_t amount, const uint64_t fee, const bool add_owner_sig)
{
    SecretKey kernel_excess = Random::CSPRNG<32>();
    m_kernelOffset.Sub(kernel_excess);
    std::vector<uint8_t> ltc_address = Random::CSPRNG<32>().vec();

    Kernel kernel = Kernel::Create(kernel_excess, fee, boost::none, PegOutCoin(amount, ltc_address), boost::none);

    if (add_owner_sig) {
        SecretKey offset = Random::CSPRNG<32>();
        m_ownerOffset.Sub(offset);

        mw::Hash msg_hash = kernel.GetHash();
        Signature sig = Schnorr::Sign(offset.data(), msg_hash);
        m_ownerSigs.push_back(SignedMessage{ msg_hash,  Keys::From(offset).PubKey(), sig });
    }

    m_kernels.push_back(std::move(kernel));
    m_amount -= amount + fee;
    return *this;
}

Tx TxBuilder::Build()
{
    assert(m_amount == 0);

    std::vector<Output> outputs;
    std::transform(
        m_outputs.cbegin(), m_outputs.cend(),
        std::back_inserter(outputs),
        [](const TxOutput& output) { return output.GetOutput(); }
    );

    auto pTransaction = mw::Transaction::Create(
        m_kernelOffset.Total(),
        m_ownerOffset.Total(),
        m_inputs,
        outputs,
        m_kernels,
        m_ownerSigs
    );
    return Tx{ pTransaction, m_outputs };
}

END_NAMESPACE