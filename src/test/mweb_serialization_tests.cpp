// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <clientversion.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <mweb/mweb_node.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <version.h>

#include <test_framework/Miner.h>
#include <test_framework/TxBuilder.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <ios>
#include <memory>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> Bytes(const CDataStream& stream)
{
    return {UCharCast(stream.data()), UCharCast(stream.data()) + stream.size()};
}

template <typename T>
std::vector<uint8_t> Encode(const T& object, const int flags = 0, const int type = SER_NETWORK)
{
    CDataStream stream(type, PROTOCOL_VERSION | flags);
    stream << object;
    return Bytes(stream);
}

template <typename T>
T Decode(const std::vector<uint8_t>& bytes, const int flags = 0, const int type = SER_NETWORK)
{
    CDataStream stream(bytes, type, PROTOCOL_VERSION | flags);
    T object;
    stream >> object;
    BOOST_REQUIRE(stream.empty());
    return object;
}

void CheckTransactionRoundTrip(const CMutableTransaction& original)
{
    const auto bytes = Encode(original);
    const auto decoded = Decode<CMutableTransaction>(bytes);
    const CTransaction before{original}, after{decoded};
    BOOST_CHECK(Encode(decoded) == bytes);
    BOOST_CHECK(after.GetHash() == before.GetHash());
    BOOST_CHECK(after.GetWitnessHash() == before.GetWitnessHash());
    BOOST_CHECK_EQUAL(after.HasMWEBTx(), before.HasMWEBTx());
    BOOST_CHECK_EQUAL(after.HasWitness(), before.HasWitness());
    BOOST_CHECK_EQUAL(after.IsHogEx(), before.IsHogEx());
    BOOST_CHECK_EQUAL(after.nLockTime, before.nLockTime);
}

void RejectTransaction(const std::vector<uint8_t>& bytes, const std::string& message, const int flags = 0)
{
    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION | flags);
    CMutableTransaction tx;
    BOOST_CHECK_EXCEPTION(stream >> tx, std::ios_base::failure, [&](const auto& error) {
        return std::string(error.what()).find(message) != std::string::npos;
    });
}

class MWEBSerializationTestingSetup : public BasicTestingSetup
{
public:
    MWEBSerializationTestingSetup() : BasicTestingSetup{CBaseChainParams::REGTEST}, m_miner{m_path_root / "miner"} {}

    CMutableTransaction Canonical() const
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(uint256::ONE, 3);
        tx.vout.emplace_back(COIN, P2WSH_OP_TRUE);
        tx.nLockTime = 17;
        return tx;
    }

    CMutableTransaction Hybrid() const
    {
        const auto pegin = test::Tx::CreatePegIn(10 * COIN);
        auto tx = Canonical();
        tx.vin.front().scriptWitness.stack = {WITNESS_STACK_ELEM_OP_TRUE};
        tx.vout = {CTxOut{10 * COIN, GetScriptForPegin(pegin.GetKernels().front().GetKernelID())}};
        tx.mweb_tx = mw::MutableTx::From(*pegin.GetTransaction());
        return tx;
    }

    CMutableTransaction PureMWEB() const
    {
        const auto transfer = test::TxBuilder().AddInput(3 * COIN).AddOutput(2 * COIN - 1000)
            .AddPegoutKernel({PegOutCoin{COIN, P2WSH_OP_TRUE}}, 1000).Build();
        CMutableTransaction tx;
        tx.mweb_tx = mw::MutableTx::From(*transfer.GetTransaction());
        return tx;
    }

    CMutableTransaction HogEx() const
    {
        auto tx = Canonical();
        tx.m_hogEx = true;
        tx.vout.front().scriptPubKey = CScript() << OP_8 << std::vector<uint8_t>(32, 1);
        return tx;
    }

    CBlock Block()
    {
        const auto pegin = test::Tx::CreatePegIn(10 * COIN);
        CBlock block;
        block.nVersion = 4;
        block.nTime = 1'601'450'001;
        block.nBits = 0x207fffff;
        block.mweb_block = MWEB::Block{m_miner.MineBlock(100, {pegin}).GetBlock()};
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin.front().scriptSig = CScript() << 100 << OP_0;
        coinbase.vout.emplace_back(50 * COIN, P2WSH_OP_TRUE);
        auto deposit = Canonical();
        deposit.vout = {CTxOut{10 * COIN, GetScriptForPegin(pegin.GetKernels().front().GetKernelID())}};
        auto hogex = HogEx();
        hogex.vin = {CTxIn{COutPoint{CTransaction{deposit}.GetHash(), 0}}};
        hogex.vout = {CTxOut{10 * COIN, CScript() << OP_8 << block.mweb_block.GetHash().vec()}};
        block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(deposit), MakeTransactionRef(hogex)};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        return block;
    }

    CBlockUndo Undo()
    {
        const auto block = Block();
        const auto& output = block.mweb_block.m_block->GetOutputs().front();
        CBlockUndo undo;
        undo.vtxundo.resize(1);
        undo.vtxundo.front().vprevout.emplace_back(CTxOut{COIN, P2WSH_OP_TRUE}, 99, false, true);
        undo.mwundo = std::make_shared<mw::BlockUndo>(block.mweb_block.GetMWEBHeader(),
            std::vector<mw::Coin::CPtr>{std::make_shared<mw::Coin>(99, mmr::LeafIndex::At(7), output)},
            std::vector<mw::Hash>{output.GetOutputID()});
        return undo;
    }

    test::Miner m_miner;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(mweb_serialization_tests, MWEBSerializationTestingSetup)

// A pure-MWEB transfer preserves its inputs, outputs, peg-out kernel, offsets, and identity through the wire format.
BOOST_AUTO_TEST_CASE(pure_mweb_transaction_round_trip)
{
    const auto tx = PureMWEB();
    const auto bytes = Encode(tx);
    BOOST_REQUIRE_EQUAL(bytes.at(4), 0);
    BOOST_CHECK_EQUAL(bytes.at(5), 8);
    CheckTransactionRoundTrip(tx);
    TxValidationState state;
    BOOST_CHECK(MWEB::Node::CheckTransaction(CTransaction{Decode<CMutableTransaction>(bytes)}, state));
}

// A hybrid carries canonical witnesses before its MWEB payload, with both optional-data bits set and lock time last.
BOOST_AUTO_TEST_CASE(hybrid_wire_field_order)
{
    const auto tx = Hybrid();
    CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
    expected << tx.nVersion << uint8_t{0} << uint8_t{9} << tx.vin << tx.vout;
    for (const auto& input : tx.vin) expected << input.scriptWitness.stack;
    expected << tx.mweb_tx << tx.nLockTime;
    BOOST_CHECK(Encode(tx) == Bytes(expected));
    CheckTransactionRoundTrip(tx);
}

// MWEB data does not require a canonical witness: a witnessless hybrid uses only optional-data bit 8.
BOOST_AUTO_TEST_CASE(witnessless_hybrid_round_trip)
{
    auto tx = Hybrid();
    tx.vin.front().scriptWitness.SetNull();
    BOOST_CHECK_EQUAL(Encode(tx).at(5), 8);
    CheckTransactionRoundTrip(tx);
}

// Every canonical witness stack survives when a hybrid has several inputs, including an intentionally empty stack.
BOOST_AUTO_TEST_CASE(hybrid_preserves_multiple_witness_stacks)
{
    auto tx = Hybrid();
    tx.vin.emplace_back(uint256::ONE, 4);
    tx.vin.emplace_back(uint256::ONE, 5);
    tx.vin.back().scriptWitness.stack = {{1, 2}, {}, {3, 4, 5}};
    const auto decoded = Decode<CMutableTransaction>(Encode(tx));
    BOOST_REQUIRE_EQUAL(decoded.vin.size(), 3U);
    for (size_t i = 0; i < tx.vin.size(); ++i) BOOST_CHECK(decoded.vin[i].scriptWitness.stack == tx.vin[i].scriptWitness.stack);
    CheckTransactionRoundTrip(tx);
}

// Stripping canonical witnesses keeps the hybrid's MWEB data and emits a payload readable by an MWEB-aware peer.
BOOST_AUTO_TEST_CASE(witness_stripping_preserves_mweb)
{
    const auto tx = Hybrid();
    const auto decoded = Decode<CMutableTransaction>(Encode(tx, SERIALIZE_TRANSACTION_NO_WITNESS));
    BOOST_CHECK(!decoded.HasWitness());
    BOOST_CHECK(!decoded.mweb_tx.IsNull());
    BOOST_CHECK(CTransaction{decoded}.mweb_tx.m_transaction->GetHash() == CTransaction{tx}.mweb_tx.m_transaction->GetHash());
    BOOST_CHECK(CTransaction{decoded}.GetHash() == CTransaction{tx}.GetHash());
}

// Stripping MWEB data leaves canonical witnesses and both canonical transaction identifiers unchanged.
BOOST_AUTO_TEST_CASE(mweb_stripping_preserves_canonical_witness_and_ids)
{
    const auto tx = Hybrid();
    const auto decoded = Decode<CMutableTransaction>(Encode(tx, SERIALIZE_NO_MWEB));
    BOOST_CHECK(decoded.mweb_tx.IsNull());
    BOOST_CHECK(decoded.HasWitness());
    BOOST_CHECK(CTransaction{decoded}.GetHash() == CTransaction{tx}.GetHash());
    BOOST_CHECK(CTransaction{decoded}.GetWitnessHash() == CTransaction{tx}.GetWitnessHash());
    BOOST_CHECK_LT(Encode(decoded).size(), Encode(tx).size());
}

// Stripping both extensions produces exactly the legacy transaction encoding, with no optional-data marker.
BOOST_AUTO_TEST_CASE(stripping_both_extensions_matches_legacy_encoding)
{
    const auto tx = Hybrid();
    auto legacy = tx;
    legacy.mweb_tx.SetNull();
    legacy.vin.front().scriptWitness.SetNull();
    BOOST_CHECK(Encode(tx, SERIALIZE_NO_MWEB | SERIALIZE_TRANSACTION_NO_WITNESS) == Encode(legacy));
    CheckTransactionRoundTrip(legacy);
}

// Changing a hybrid's MWEB payload changes its wire bytes but neither canonical txid nor canonical witness hash.
BOOST_AUTO_TEST_CASE(hybrid_ids_exclude_mweb_payload)
{
    const auto original = Hybrid();
    auto changed = original;
    changed.mweb_tx.stealth_offset = BlindingFactor::Random();
    BOOST_CHECK(Encode(original) != Encode(changed));
    BOOST_CHECK(CTransaction{original}.GetHash() == CTransaction{changed}.GetHash());
    BOOST_CHECK(CTransaction{original}.GetWitnessHash() == CTransaction{changed}.GetWitnessHash());
}

// Unlike a hybrid, a pure-MWEB transaction takes both identifiers from the hash of its MWEB payload.
BOOST_AUTO_TEST_CASE(pure_mweb_ids_commit_to_mweb_payload)
{
    const CTransaction original{PureMWEB()};
    BOOST_CHECK(original.GetHash() == uint256{original.mweb_tx.m_transaction->GetHash().vec()});
    BOOST_CHECK(original.GetWitnessHash() == original.GetHash());
    CMutableTransaction changed{original};
    changed.mweb_tx.stealth_offset = BlindingFactor::Random();
    BOOST_CHECK(CTransaction{changed}.GetHash() != original.GetHash());
}

// Changing a hybrid's canonical witness changes only its witness hash, not its txid or MWEB payload hash.
BOOST_AUTO_TEST_CASE(hybrid_witness_changes_only_witness_hash)
{
    const CTransaction original{Hybrid()};
    CMutableTransaction changed{original};
    changed.vin.front().scriptWitness.stack.front().push_back(42);
    const CTransaction updated{changed};
    BOOST_CHECK(updated.GetHash() == original.GetHash());
    BOOST_CHECK(updated.GetWitnessHash() != original.GetWitnessHash());
    BOOST_CHECK(updated.mweb_tx.m_transaction->GetHash() == original.mweb_tx.m_transaction->GetHash());
}

// A HogEx uses the MWEB flag with an absent transaction payload; the marker survives but does not affect its txid.
BOOST_AUTO_TEST_CASE(hogex_marker_round_trip_and_stripping)
{
    const auto tx = HogEx();
    CheckTransactionRoundTrip(tx);
    const auto stripped = Decode<CMutableTransaction>(Encode(tx, SERIALIZE_NO_MWEB));
    BOOST_CHECK(!stripped.m_hogEx);
    BOOST_CHECK(stripped.mweb_tx.IsNull());
    BOOST_CHECK(CTransaction{stripped}.GetHash() == CTransaction{tx}.GetHash());
}

// Unknown optional-data bits are rejected even when the known HogEx portion of the transaction is well formed.
BOOST_AUTO_TEST_CASE(unknown_transaction_flags_are_rejected)
{
    const auto bytes = Encode(HogEx());
    for (const uint8_t unknown : {uint8_t{2}, uint8_t{4}, uint8_t{16}, uint8_t{128}}) {
        BOOST_TEST_CONTEXT("unknown flag " << unsigned{unknown}) {
            auto invalid = bytes;
            invalid.at(5) |= unknown;
            RejectTransaction(invalid, "Unknown transaction optional data");
        }
    }
}

// A reader explicitly disabling MWEB cannot silently accept a transaction containing MWEB optional data.
BOOST_AUTO_TEST_CASE(mweb_disabled_reader_rejects_mweb_payload)
{
    RejectTransaction(Encode(Hybrid()), "Unknown transaction optional data", SERIALIZE_NO_MWEB);
}

// The witness bit cannot be set when all canonical witness stacks are empty, even if MWEB data follows.
BOOST_AUTO_TEST_CASE(superfluous_witness_record_is_rejected)
{
    auto tx = Hybrid();
    tx.vin.front().scriptWitness.SetNull();
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << tx.nVersion << uint8_t{0} << uint8_t{9} << tx.vin << tx.vout;
    stream << tx.vin.front().scriptWitness.stack << tx.mweb_tx << tx.nLockTime;
    RejectTransaction(Bytes(stream), "Superfluous witness record");
}

// An absent MWEB payload denotes HogEx only when the transaction has at least one canonical output.
BOOST_AUTO_TEST_CASE(hogex_without_outputs_is_rejected)
{
    auto tx = HogEx();
    tx.vout.clear();
    RejectTransaction(Encode(tx), "Missing HogEx output");
}

// A present MWEB transaction must contain a kernel; an empty body is not another encoding of an absent payload.
BOOST_AUTO_TEST_CASE(present_mweb_transaction_requires_kernel)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << int32_t{2} << uint8_t{0} << uint8_t{8} << std::vector<CTxIn>{} << std::vector<CTxOut>{};
    stream << MWEB::Tx{std::make_shared<mw::Transaction>()} << uint32_t{0};
    RejectTransaction(Bytes(stream), "Transaction requires at least one kernel");
}

// Truncating the transaction envelope, MWEB offsets, or final lock time must fail instead of yielding a partial transaction.
BOOST_AUTO_TEST_CASE(truncated_hybrid_fields_are_rejected)
{
    const auto tx = Hybrid();
    const auto bytes = Encode(tx);
    CDataStream prefix(SER_NETWORK, PROTOCOL_VERSION);
    prefix << tx.nVersion << uint8_t{0} << uint8_t{9} << tx.vin << tx.vout << tx.vin.front().scriptWitness.stack;
    for (const size_t length : {size_t{0}, size_t{4}, size_t{6}, prefix.size(), prefix.size() + 1,
                               prefix.size() + 32, prefix.size() + 64, bytes.size() - 4, bytes.size() - 1}) {
        BOOST_TEST_CONTEXT("prefix length " << length) {
            CDataStream stream(std::vector<uint8_t>(bytes.begin(), bytes.begin() + length), SER_NETWORK, PROTOCOL_VERSION);
            CMutableTransaction decoded;
            BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
        }
    }
}

// Reading a legacy transaction into a previously populated hybrid must discard the previous MWEB payload.
BOOST_AUTO_TEST_CASE(reused_transaction_clears_old_mweb_payload)
{
    const auto legacy = Canonical();
    for (const int flags : {0, SERIALIZE_NO_MWEB, SERIALIZE_TRANSACTION_NO_WITNESS,
                           SERIALIZE_NO_MWEB | SERIALIZE_TRANSACTION_NO_WITNESS}) {
        BOOST_TEST_CONTEXT("reader flags " << flags) {
            auto decoded = Hybrid();
            CDataStream stream(Encode(legacy), SER_NETWORK, PROTOCOL_VERSION | flags);
            stream >> decoded;
            BOOST_CHECK(decoded.mweb_tx.IsNull());
            BOOST_CHECK(Encode(decoded) == Encode(legacy));
            BOOST_CHECK(stream.empty());
        }
    }
}

// Reading an ordinary transaction into a former HogEx must clear the old HogEx marker.
BOOST_AUTO_TEST_CASE(reused_transaction_clears_old_hogex_marker)
{
    auto decoded = HogEx();
    const auto legacy = Canonical();
    CDataStream stream(Encode(legacy), SER_NETWORK, PROTOCOL_VERSION);
    stream >> decoded;
    BOOST_CHECK(!decoded.m_hogEx);
    BOOST_CHECK(Encode(decoded) == Encode(legacy));
}

// Switching from hybrid to HogEx to pure MWEB must replace the payload and marker, not combine state from adjacent records.
BOOST_AUTO_TEST_CASE(reused_transaction_handles_mweb_and_hogex_transitions)
{
    auto decoded = Hybrid();
    const std::vector<CMutableTransaction> records{HogEx(), PureMWEB(), Hybrid(), Canonical()};
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    for (const auto& record : records) stream << record;
    for (const auto& record : records) {
        stream >> decoded;
        BOOST_CHECK_EQUAL(decoded.m_hogEx, record.m_hogEx);
        BOOST_CHECK_EQUAL(decoded.mweb_tx.IsNull(), record.mweb_tx.IsNull());
        BOOST_CHECK(Encode(decoded) == Encode(record));
    }
    BOOST_CHECK(stream.empty());
}

// Optional MWEB wrappers round-trip both present and absent values without inventing an empty transaction or block.
BOOST_AUTO_TEST_CASE(optional_wrappers_round_trip)
{
    const MWEB::Tx tx = CTransaction{PureMWEB()}.mweb_tx;
    const auto block = Block().mweb_block;
    BOOST_CHECK(Encode(Decode<MWEB::Tx>(Encode(tx))) == Encode(tx));
    BOOST_CHECK(Encode(Decode<MWEB::Block>(Encode(block))) == Encode(block));
    BOOST_CHECK(Encode(MWEB::Tx{}) == std::vector<uint8_t>{0});
    BOOST_CHECK(Decode<MWEB::Tx>({0}).IsNull());
    BOOST_CHECK(Decode<MWEB::Block>({0}).IsNull());
}

// Every accepted absent marker clears existing immutable and mutable MWEB transactions and blocks when their wrappers are reused.
BOOST_AUTO_TEST_CASE(absent_optional_marker_clears_existing_payload)
{
    const auto original_tx = PureMWEB();
    const auto original_block = Block().mweb_block;
    for (const uint8_t marker : {uint8_t{0}, uint8_t{2}, uint8_t{255}}) {
        BOOST_TEST_CONTEXT("absent marker " << unsigned{marker}) {
            auto tx = CTransaction{original_tx}.mweb_tx;
            auto mutable_tx = original_tx.mweb_tx;
            auto block = original_block;
            CDataStream stream(std::vector<uint8_t>{marker, marker, marker}, SER_NETWORK, PROTOCOL_VERSION);
            stream >> tx >> mutable_tx >> block;
            BOOST_CHECK(tx.IsNull());
            BOOST_CHECK(mutable_tx.IsNull());
            BOOST_CHECK(Encode(mutable_tx) == std::vector<uint8_t>{0});
            BOOST_CHECK(block.IsNull());
            BOOST_CHECK(stream.empty());
        }
    }
}

// Preserve the documented compatibility rule: only marker 1 means present; other marker bytes mean absent.
BOOST_AUTO_TEST_CASE(noncanonical_optional_markers_follow_existing_wire_compatibility)
{
    for (const uint8_t marker : {uint8_t{0}, uint8_t{2}, uint8_t{255}}) {
        BOOST_CHECK(Decode<MWEB::Tx>({marker}).IsNull());
        BOOST_CHECK(Decode<MWEB::Block>({marker}).IsNull());
    }
}

// A complete block preserves the extension body, HogEx marker, canonical merkle root, and block hash on disk and wire.
BOOST_AUTO_TEST_CASE(block_round_trip_on_disk_and_wire)
{
    const auto block = Block();
    for (const int type : {SER_NETWORK, SER_DISK}) {
        const auto bytes = Encode(block, 0, type);
        const auto decoded = Decode<CBlock>(bytes, 0, type);
        BOOST_CHECK(Encode(decoded, 0, type) == bytes);
        BOOST_CHECK(decoded.GetHash() == block.GetHash());
        BOOST_CHECK(BlockMerkleRoot(decoded) == block.hashMerkleRoot);
        BOOST_REQUIRE(decoded.GetHogEx());
        BOOST_CHECK(decoded.mweb_block.GetHash() == block.mweb_block.GetHash());
    }
}

// Stripping a block removes its extension and HogEx marker while preserving canonical hashes and merkle commitments.
BOOST_AUTO_TEST_CASE(block_stripping_preserves_canonical_commitments)
{
    const auto block = Block();
    const auto stripped = Decode<CBlock>(Encode(block, SERIALIZE_NO_MWEB));
    BOOST_CHECK(stripped.mweb_block.IsNull());
    BOOST_CHECK(!stripped.GetHogEx());
    BOOST_CHECK(stripped.GetHash() == block.GetHash());
    BOOST_CHECK(BlockMerkleRoot(stripped) == BlockMerkleRoot(block));
    BOOST_REQUIRE_EQUAL(stripped.vtx.size(), block.vtx.size());
    for (size_t i = 0; i < block.vtx.size(); ++i) BOOST_CHECK(stripped.vtx[i]->GetHash() == block.vtx[i]->GetHash());
}

// A final HogEx triggers an extension-presence marker even when the extension is absent; consensus checks decide validity later.
BOOST_AUTO_TEST_CASE(hogex_block_with_absent_extension_round_trip)
{
    auto block = Block();
    block.mweb_block.SetNull();
    const auto decoded = Decode<CBlock>(Encode(block));
    BOOST_REQUIRE(decoded.GetHogEx());
    BOOST_CHECK(decoded.mweb_block.IsNull());
    BOOST_CHECK(Encode(decoded) == Encode(block));
}

// Without a final HogEx, legacy block serialization does not append any MWEB payload or presence marker.
BOOST_AUTO_TEST_CASE(legacy_block_has_no_extension_trailer)
{
    auto block = Block();
    block.vtx.pop_back();
    CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
    expected << block.GetBlockHeader() << block.vtx;
    BOOST_CHECK(Encode(block) == Bytes(expected));
    BOOST_CHECK(Decode<CBlock>(Encode(block)).mweb_block.IsNull());
}

// Reading a legacy block clears a reused block's old extension and cached validation result.
BOOST_AUTO_TEST_CASE(reused_block_clears_old_extension)
{
    auto decoded = Block();
    decoded.fChecked = true;
    auto legacy = decoded;
    legacy.vtx.pop_back();
    legacy.mweb_block.SetNull();
    CDataStream stream(Encode(legacy), SER_NETWORK, PROTOCOL_VERSION);
    stream >> decoded;
    BOOST_CHECK(decoded.mweb_block.IsNull());
    BOOST_CHECK(!decoded.fChecked);
    BOOST_CHECK(Encode(decoded) == Encode(legacy));
    BOOST_CHECK(stream.empty());
}

// Explicitly absent and stripped extensions both replace the old payload; a later complete record restores it normally.
BOOST_AUTO_TEST_CASE(reused_block_handles_absent_and_stripped_extensions)
{
    const auto complete = Block();
    auto absent = complete;
    absent.mweb_block.SetNull();
    for (const int flags : {0, SERIALIZE_NO_MWEB}) {
        BOOST_TEST_CONTEXT("reader flags " << flags) {
            auto decoded = complete;
            const auto bytes = Encode(flags == 0 ? absent : complete, flags);
            CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION | flags);
            stream >> decoded;
            BOOST_CHECK(decoded.mweb_block.IsNull());
            BOOST_CHECK(Encode(decoded, flags) == bytes);
            BOOST_CHECK(stream.empty());

            CDataStream restored(Encode(complete), SER_NETWORK, PROTOCOL_VERSION);
            restored >> decoded;
            BOOST_CHECK(Encode(decoded) == Encode(complete));
            BOOST_CHECK(restored.empty());
        }
    }
}

// Removing any part of an advertised extension block must fail deserialization, not silently turn it into a legacy block.
BOOST_AUTO_TEST_CASE(truncated_block_extension_is_rejected)
{
    const auto block = Block();
    const auto bytes = Encode(block);
    CDataStream prefix(SER_NETWORK, PROTOCOL_VERSION);
    prefix << block.GetBlockHeader() << block.vtx;
    for (const size_t length : {prefix.size(), prefix.size() + 1, bytes.size() - 1}) {
        CDataStream stream(std::vector<uint8_t>(bytes.begin(), bytes.begin() + length), SER_NETWORK, PROTOCOL_VERSION);
        CBlock decoded;
        BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
    }
}

// Disk block indexes retain the MWEB header, HogEx txid, and locked amount when BLOCK_HAVE_MWEB is set.
BOOST_AUTO_TEST_CASE(disk_block_index_preserves_mweb_metadata)
{
    const auto block = Block();
    CBlockIndex index{block};
    index.nHeight = 100;
    index.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO | BLOCK_HAVE_MWEB;
    index.nTx = block.vtx.size();
    index.nFile = 2;
    index.nDataPos = 123;
    index.nUndoPos = 456;
    index.mweb_header = block.mweb_block.GetMWEBHeader();
    index.hogex_hash = block.GetHogEx()->GetHash();
    index.mweb_amount = block.GetHogEx()->vout.front().nValue;
    const CDiskBlockIndex disk{&index};
    const auto decoded = Decode<CDiskBlockIndex>(Encode(disk, 0, SER_DISK), 0, SER_DISK);
    BOOST_REQUIRE(decoded.mweb_header);
    BOOST_CHECK(*decoded.mweb_header == *index.mweb_header);
    BOOST_CHECK(decoded.hogex_hash == index.hogex_hash);
    BOOST_CHECK_EQUAL(decoded.mweb_amount, index.mweb_amount);
    BOOST_CHECK_EQUAL(decoded.nStatus, index.nStatus);
    BOOST_CHECK_EQUAL(decoded.nDataPos, index.nDataPos);
    BOOST_CHECK_EQUAL(decoded.nUndoPos, index.nUndoPos);
    BOOST_CHECK(decoded.ConstructBlockHash() == block.GetHash());
}

// Legacy disk block indexes omit MWEB metadata, even if the in-memory source happens to have MWEB fields populated.
BOOST_AUTO_TEST_CASE(disk_block_index_without_mweb_flag_uses_legacy_format)
{
    const auto block = Block();
    CBlockIndex index{block};
    index.nHeight = 100;
    index.nStatus = BLOCK_VALID_SCRIPTS;
    index.mweb_header = block.mweb_block.GetMWEBHeader();
    index.hogex_hash = block.GetHogEx()->GetHash();
    index.mweb_amount = 10 * COIN;
    const auto decoded = Decode<CDiskBlockIndex>(Encode(CDiskBlockIndex{&index}, 0, SER_DISK), 0, SER_DISK);
    BOOST_CHECK(!decoded.mweb_header);
    BOOST_CHECK(decoded.hogex_hash.IsNull());
    BOOST_CHECK_EQUAL(decoded.mweb_amount, 0);
}

// The peg-out bit is independent of coinbase status and height in both the UTXO and transaction-undo formats.
BOOST_AUTO_TEST_CASE(pegout_coin_metadata_round_trip)
{
    for (const int height : {0, 1, 100, 1'000'000}) {
        for (const bool coinbase : {false, true}) {
            for (const bool pegout : {false, true}) {
                BOOST_TEST_CONTEXT("height " << height << ", coinbase " << coinbase << ", pegout " << pegout) {
                    const Coin coin{CTxOut{12345, P2WSH_OP_TRUE}, height, coinbase, pegout};
                    const auto decoded = Decode<Coin>(Encode(coin, 0, SER_DISK), 0, SER_DISK);
                    CTxUndo undo;
                    undo.vprevout.push_back(coin);
                    const auto decoded_undo = Decode<CTxUndo>(Encode(undo, 0, SER_DISK), 0, SER_DISK);
                    BOOST_REQUIRE_EQUAL(decoded_undo.vprevout.size(), 1U);
                    for (const Coin& recovered : {decoded, decoded_undo.vprevout.front()}) {
                        BOOST_CHECK_EQUAL(recovered.nHeight, height);
                        BOOST_CHECK_EQUAL(recovered.IsCoinBase(), coinbase);
                        BOOST_CHECK_EQUAL(recovered.IsPegout(), pegout);
                        BOOST_CHECK(recovered.out == coin.out);
                    }
                }
            }
        }
    }
}

// Length-delimited undo decoding preserves both canonical undo and MWEB rewind data without consuming the next record.
BOOST_AUTO_TEST_CASE(block_undo_round_trip_respects_record_boundary)
{
    const auto undo = Undo();
    const auto bytes = Encode(undo, 0, SER_DISK);
    CDataStream stream(bytes, SER_DISK, PROTOCOL_VERSION);
    stream << uint32_t{0x12345678};
    CBlockUndo decoded;
    UnserializeBlockUndo(decoded, stream, bytes.size());
    BOOST_CHECK(Encode(decoded, 0, SER_DISK) == bytes);
    BOOST_REQUIRE(decoded.mwundo);
    BOOST_REQUIRE_EQUAL(decoded.mwundo->GetCoinsSpent().size(), 1U);
    BOOST_CHECK_EQUAL(decoded.mwundo->GetCoinsSpent().front()->GetLeafIndex().Get(), 7U);
    uint32_t sentinel;
    stream >> sentinel;
    BOOST_CHECK_EQUAL(sentinel, 0x12345678U);
    BOOST_CHECK(stream.empty());
}

// Undo predating MWEB has no extension tail, and its declared length must keep the next record untouched.
BOOST_AUTO_TEST_CASE(legacy_block_undo_has_no_mweb_tail)
{
    auto undo = Undo();
    undo.mwundo.reset();
    const auto bytes = Encode(undo, 0, SER_DISK);
    CDataStream stream(bytes, SER_DISK, PROTOCOL_VERSION);
    stream << uint32_t{42};
    CBlockUndo decoded;
    UnserializeBlockUndo(decoded, stream, bytes.size());
    BOOST_CHECK(!decoded.mwundo);
    BOOST_CHECK(Encode(decoded, 0, SER_DISK) == bytes);
    uint32_t sentinel;
    stream >> sentinel;
    BOOST_CHECK_EQUAL(sentinel, 42U);
}

// Reusing an undo object replaces both canonical entries and its optional MWEB tail without consuming the next record.
BOOST_AUTO_TEST_CASE(reused_block_undo_replaces_previous_record)
{
    auto decoded = Undo();
    CBlockUndo legacy;
    legacy.vtxundo.resize(1);
    legacy.vtxundo.front().vprevout.emplace_back(CTxOut{2 * COIN, P2WSH_OP_TRUE}, 3, false);
    const std::vector<CBlockUndo> records{legacy, Undo(), CBlockUndo{}};
    for (const auto& record : records) {
        const auto bytes = Encode(record, 0, SER_DISK);
        CDataStream stream(bytes, SER_DISK, PROTOCOL_VERSION);
        stream << uint32_t{42};
        UnserializeBlockUndo(decoded, stream, bytes.size());
        BOOST_CHECK_EQUAL(bool(decoded.mwundo), bool(record.mwundo));
        BOOST_CHECK_EQUAL(decoded.vtxundo.size(), record.vtxundo.size());
        BOOST_CHECK(Encode(decoded, 0, SER_DISK) == bytes);
        uint32_t sentinel;
        stream >> sentinel;
        BOOST_CHECK_EQUAL(sentinel, 42U);
        BOOST_CHECK(stream.empty());
    }
}

// Reusing MWEB undo for the first extension block clears the previous-header pointer along with the old coin lists.
BOOST_AUTO_TEST_CASE(reused_mweb_undo_clears_absent_previous_header)
{
    auto decoded = *Undo().mwundo;
    BOOST_REQUIRE(decoded.GetPreviousHeader());
    const mw::BlockUndo first_block{nullptr, {}, {}};
    CDataStream stream(Encode(first_block, 0, SER_DISK), SER_DISK, PROTOCOL_VERSION);
    stream >> decoded;
    BOOST_CHECK(!decoded.GetPreviousHeader());
    BOOST_CHECK(decoded.GetCoinsSpent().empty());
    BOOST_CHECK(decoded.GetCoinsAdded().empty());
    BOOST_CHECK(Encode(decoded, 0, SER_DISK) == Encode(first_block, 0, SER_DISK));
    BOOST_CHECK(stream.empty());
}

// Truncated MWEB undo must not be accepted as a complete rewind record.
BOOST_AUTO_TEST_CASE(truncated_mweb_undo_is_rejected)
{
    const auto bytes = Encode(Undo(), 0, SER_DISK);
    CDataStream stream(std::vector<uint8_t>(bytes.begin(), bytes.end() - 1), SER_DISK, PROTOCOL_VERSION);
    CBlockUndo decoded;
    BOOST_CHECK_THROW(UnserializeBlockUndo(decoded, stream, bytes.size()), std::ios_base::failure);
}

// Network UTXO formats share a compact leaf index but encode either the full output, its ID, or its compact proof commitment.
BOOST_AUTO_TEST_CASE(network_coin_formats_have_explicit_field_layouts)
{
    const auto tx = test::Tx::CreatePegIn(COIN);
    const auto coin = std::make_shared<mw::Coin>(100, mmr::LeafIndex::At(253), tx.GetOutputs().front().GetOutput());
    for (const uint8_t format : {mw::NetCoin::FULL_COIN, mw::NetCoin::HASH_ONLY, mw::NetCoin::COMPACT_COIN}) {
        CDataStream expected(SER_NETWORK, PROTOCOL_VERSION);
        expected << COMPACTSIZE(coin->GetLeafIndex().Get());
        if (format == mw::NetCoin::FULL_COIN) {
            expected << coin->GetOutput();
        } else if (format == mw::NetCoin::HASH_ONLY) {
            expected << coin->GetOutputID();
        } else {
            expected << coin->GetCommitment() << coin->GetSenderPubKey() << coin->GetReceiverPubKey();
            expected << coin->GetOutputMessage() << coin->GetRangeProof()->GetHash() << coin->GetSignature();
        }
        BOOST_CHECK(Encode(mw::NetCoin{format, coin}) == Bytes(expected));
    }
    BOOST_CHECK_THROW(Encode(mw::NetCoin{255, coin}), std::ios_base::failure);
}

BOOST_AUTO_TEST_SUITE_END()
