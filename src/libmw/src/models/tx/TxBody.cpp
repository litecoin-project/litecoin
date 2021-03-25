#include <mw/models/tx/TxBody.h>
#include <mw/exceptions/ValidationException.h>
#include <mw/consensus/Weight.h>

#include <unordered_set>
#include <numeric>

std::vector<PegInCoin> TxBody::GetPegIns() const noexcept
{
    std::vector<PegInCoin> pegins;
    for (const Kernel& kernel : m_kernels) {
        if (kernel.HasPegIn()) {
            pegins.push_back(PegInCoin(kernel.GetPegIn(), kernel.GetCommitment()));
        }
    }

    return pegins;
}

std::vector<Output> TxBody::GetPegInOutputs() const noexcept
{
    std::vector<Output> peggedIn;
    std::copy_if(
        m_outputs.cbegin(), m_outputs.cend(),
        std::back_inserter(peggedIn),
        [](const Output& output) -> bool { return output.IsPeggedIn(); }
    );

    return peggedIn;
}

uint64_t TxBody::GetPegInAmount() const noexcept
{
    return std::accumulate(
        m_kernels.cbegin(), m_kernels.cend(), (uint64_t)0,
        [](const uint64_t sum, const auto& kernel) noexcept { return sum + kernel.GetPegIn(); }
    );
}

std::vector<PegOutCoin> TxBody::GetPegOuts() const noexcept
{
    std::vector<PegOutCoin> pegouts;
    for (const Kernel& kernel : m_kernels) {
        if (kernel.HasPegOut()) {
            pegouts.push_back(kernel.GetPegOut().value());
        }
    }
    return pegouts;
}

uint64_t TxBody::GetTotalFee() const noexcept
{
    return std::accumulate(
        m_kernels.cbegin(), m_kernels.cend(), (uint64_t)0,
        [](const uint64_t sum, const auto& kernel) noexcept { return sum + kernel.GetFee(); }
    );
}

int64_t TxBody::GetSupplyChange() const noexcept
{
    int64_t coins_added = 0;
    for (const Kernel& kernel : m_kernels) {
        coins_added += kernel.GetSupplyChange();
    }

    return coins_added;
}

Serializer& TxBody::Serialize(Serializer& serializer) const noexcept
{
    return serializer
        .AppendVec<Input>(m_inputs)
        .AppendVec<Output>(m_outputs)
        .AppendVec<Kernel>(m_kernels)
        .AppendVec<SignedMessage>(m_ownerSigs);
}

TxBody TxBody::Deserialize(Deserializer& deserializer)
{
    std::vector<Input> inputs = deserializer.ReadVec<Input>();
    std::vector<Output> outputs = deserializer.ReadVec<Output>();
    std::vector<Kernel> kernels = deserializer.ReadVec<Kernel>();
    std::vector<SignedMessage> owner_sigs = deserializer.ReadVec<SignedMessage>();
    return TxBody(std::move(inputs), std::move(outputs), std::move(kernels), std::move(owner_sigs));
}

void TxBody::Validate() const
{
    // Verify weight
    if (Weight::ExceedsMaximum(*this)) {
        ThrowValidation(EConsensusError::BLOCK_WEIGHT);
    }

    // Verify no kernel's extra_data or pegout scriptPubKey exceeds max size
    bool extra_data_exceeds_max = std::any_of(
        m_kernels.cbegin(), m_kernels.cend(),
        [](const Kernel& kernel) {
            size_t pubkeySize = kernel.GetPegOut().has_value() ? kernel.GetPegOut().value().GetScriptPubKey().size() : 4;
            return pubkeySize > 42 || pubkeySize < 4 || kernel.GetExtraData().size() > libmw::MAX_KERNEL_EXTRADATA_SIZE;
        }
    );
    if (extra_data_exceeds_max) {
        ThrowValidation(EConsensusError::BLOCK_WEIGHT);
    }

    // Verify inputs, outputs, kernels, and owner signatures are sorted
    if (!std::is_sorted(m_inputs.cbegin(), m_inputs.cend(), SortByCommitment)
        || !std::is_sorted(m_outputs.cbegin(), m_outputs.cend(), SortByCommitment)
        || !std::is_sorted(m_kernels.cbegin(), m_kernels.cend(), KernelSort)
        || !std::is_sorted(m_ownerSigs.cbegin(), m_ownerSigs.cend(), SortByHash))
    {
        ThrowValidation(EConsensusError::NOT_SORTED);
    }

    // Verify no duplicate inputs
    std::unordered_set<Commitment> input_commits;
    std::transform(
        m_inputs.cbegin(), m_inputs.cend(),
        std::inserter(input_commits, input_commits.end()),
        [](const Input& input) { return input.GetCommitment(); }
    );

    if (input_commits.size() != m_inputs.size()) {
        ThrowValidation(EConsensusError::DUPLICATE_COMMITS);
    }

    // Verify no duplicate outputs
    std::unordered_set<Commitment> output_commits;
    std::transform(
        m_outputs.cbegin(), m_outputs.cend(),
        std::inserter(output_commits, output_commits.end()),
        [](const Output& output) { return output.GetCommitment(); }
    );

    if (output_commits.size() != m_outputs.size()) {
        ThrowValidation(EConsensusError::DUPLICATE_COMMITS);
    }

    // Verify no duplicate kernels
    std::unordered_set<Commitment> kernel_commits;
    std::transform(
        m_kernels.cbegin(), m_kernels.cend(),
        std::inserter(kernel_commits, kernel_commits.end()),
        [](const Kernel& kernel) { return kernel.GetCommitment(); }
    );

    if (kernel_commits.size() != m_kernels.size()) {
        ThrowValidation(EConsensusError::DUPLICATE_COMMITS);
    }

    // Verify kernel exists with matching hash for each owner sig
    std::unordered_set<mw::Hash> kernel_hashes;
    std::transform(
        m_kernels.cbegin(), m_kernels.cend(),
        std::inserter(kernel_hashes, kernel_hashes.end()),
        [](const Kernel& kernel) { return kernel.GetHash(); }
    );

    for (const auto& owner_sig : m_ownerSigs) {
        if (kernel_hashes.find(owner_sig.GetMsgHash()) == kernel_hashes.end()) {
            ThrowValidation(EConsensusError::KERNEL_MISSING);
        }
    }

    //
    // Verify all signatures
    //
    std::vector<SignedMessage> signatures;
    std::transform(
        m_kernels.cbegin(), m_kernels.cend(),
        std::back_inserter(signatures),
        [](const Kernel& kernel) {
            PublicKey public_key = Crypto::ToPublicKey(kernel.GetCommitment());
            return SignedMessage{ kernel.GetSignatureMessage(), public_key, kernel.GetSignature() };
        }
    );

    std::transform(
        m_inputs.cbegin(), m_inputs.cend(),
        std::back_inserter(signatures),
        [](const Input& input) {
            return SignedMessage{ InputMessage(), input.GetPubKey(), input.GetSignature() };
        }
    );

    std::transform(
        m_outputs.cbegin(), m_outputs.cend(),
        std::back_inserter(signatures),
        [](const Output& output) { return output.BuildSignedMsg(); }
    );

    signatures.insert(signatures.end(), m_ownerSigs.begin(), m_ownerSigs.end());

    if (!Schnorr::BatchVerify(signatures)) {
        ThrowValidation(EConsensusError::INVALID_SIG);
    }

    //
    // Verify RangeProofs
    //
    std::vector<ProofData> rangeProofs;
    std::transform(
        m_outputs.cbegin(), m_outputs.cend(),
        std::back_inserter(rangeProofs),
        [](const Output& output) { return output.BuildProofData(); }
    );
    if (!Bulletproofs::BatchVerify(rangeProofs)) {
        ThrowValidation(EConsensusError::BULLETPROOF);
    }
}