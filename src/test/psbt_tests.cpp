// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <key.h>
#include <mw/crypto/KeyDerivation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
#include <test/data/rpc_psbt.json.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace psbt_test;

BOOST_FIXTURE_TEST_SUITE(psbt_tests, BasicTestingSetup)

namespace {

//! One raw key/value map entry. The key includes the type byte; the value is
//! the payload without its compact-size length prefix (added on write).
using RawEntry = std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;
using RawMap = std::vector<RawEntry>;

RawEntry Entry(uint8_t type, std::vector<unsigned char> value, std::vector<unsigned char> key_extra = {})
{
    std::vector<unsigned char> key{type};
    key.insert(key.end(), key_extra.begin(), key_extra.end());
    return {std::move(key), std::move(value)};
}

std::vector<unsigned char> ToBytes(const CDataStream& s)
{
    const Span<const unsigned char> bytes = MakeUCharSpan(s);
    return std::vector<unsigned char>(bytes.begin(), bytes.end());
}

//! Serialize the arguments into a payload suitable for RawEntry's value.
template <typename... Args>
std::vector<unsigned char> Payload(const Args&... args)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    SerializeMany(s, args...);
    return ToBytes(s);
}

//! Assemble raw PSBT bytes: magic, then each map's entries followed by a separator.
std::vector<unsigned char> BuildRawPSBT(const std::vector<RawMap>& maps)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << PSBT_MAGIC_BYTES;
    for (const RawMap& map : maps) {
        for (const RawEntry& entry : map) {
            s << entry.first;
            s << entry.second;
        }
        s << PSBT_SEPARATOR;
    }
    return ToBytes(s);
}

void CheckDecodeFails(const std::vector<unsigned char>& raw, const std::string& expected_error)
{
    PartiallySignedTransaction psbt;
    std::string error;
    BOOST_CHECK(!DecodeRawPSBT(psbt, MakeByteSpan(raw), error));
    BOOST_CHECK_MESSAGE(error.find(expected_error) != std::string::npos,
                        "error was \"" + error + "\", expected \"" + expected_error + "\"");
}

PartiallySignedTransaction CheckDecodeSucceeds(const std::vector<unsigned char>& raw)
{
    PartiallySignedTransaction psbt;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DecodeRawPSBT(psbt, MakeByteSpan(raw), error), error);
    return psbt;
}

//! Global map of a PSBTv0 carrying a minimal 1-in/1-out unsigned transaction.
RawMap V0GlobalMap()
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));
    mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);

    CDataStream tx_stream(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB);
    tx_stream << mtx;
    return {Entry(PSBT_GLOBAL_UNSIGNED_TX, ToBytes(tx_stream))};
}

//! Global map of a PSBTv2 with the required tx version and counts.
RawMap V2GlobalMap(uint64_t num_inputs, uint64_t num_outputs, std::optional<uint64_t> num_kernels = std::nullopt)
{
    RawMap global;
    global.push_back(Entry(PSBT_GLOBAL_TX_VERSION, Payload(int32_t{2})));
    global.push_back(Entry(PSBT_GLOBAL_INPUT_COUNT, Payload(CompactSizeWriter(num_inputs))));
    global.push_back(Entry(PSBT_GLOBAL_OUTPUT_COUNT, Payload(CompactSizeWriter(num_outputs))));
    if (num_kernels.has_value()) {
        global.push_back(Entry(PSBT_GLOBAL_MWEB_KERNEL_COUNT, Payload(CompactSizeWriter(*num_kernels))));
    }
    global.push_back(Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{2})));
    return global;
}

RawMap V2CanonicalInputMap()
{
    RawMap map;
    map.push_back(Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE)));
    map.push_back(Entry(PSBT_IN_OUTPUT_INDEX, Payload(uint32_t{0})));
    return map;
}

RawMap V2MWEBInputMap()
{
    return {Entry(PSBT_IN_MWEB_OUTPUT_ID, Payload(TestHash(9)))};
}

RawMap V2CanonicalOutputMap()
{
    const CScript script = CScript() << OP_TRUE;
    RawMap map;
    map.push_back(Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1'000})));
    map.push_back(Entry(PSBT_OUT_SCRIPT, std::vector<unsigned char>(script.begin(), script.end())));
    return map;
}

RawMap V2MWEBOutputMap()
{
    RawMap map;
    map.push_back(Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1'000})));
    map.push_back(Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('1', '2'))));
    return map;
}

//! A PSBT whose MWEB components are all present (IsComplete only checks
//! presence, not cryptographic validity): one canonical input with a final
//! witness, one all-fields MWEB input/output, one all-fields kernel, and
//! both global offsets.
PartiallySignedTransaction PresenceCompletePSBT()
{
    PartiallySignedTransaction psbt = AllFieldsPSBT();
    psbt.inputs[0].final_script_witness.stack.push_back({0x01});
    BOOST_REQUIRE(psbt.IsComplete());
    return psbt;
}

} // namespace

// ---------------------------------------------------------------------------
// Golden-vector serialization
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(allfields_golden_roundtrip)
{
    const PartiallySignedTransaction built = AllFieldsPSBT();

    // The builder is deterministic: its serialization is pinned to freeze the
    // wire format of every MWEB keytype.
    BOOST_CHECK_EQUAL(SerHex(built), PSBT_V2_ALLFIELDS);

    const PartiallySignedTransaction decoded = DecodeHexPSBT(PSBT_V2_ALLFIELDS);
    BOOST_CHECK_EQUAL(SerHex(decoded), PSBT_V2_ALLFIELDS);

    // Spot-check decoded fields against the builder's inputs.
    BOOST_REQUIRE_EQUAL(decoded.inputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(decoded.outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(decoded.kernels.size(), 1U);
    BOOST_CHECK(decoded.inputs[1].mweb_output_id == std::optional<mw::Hash>{TestHash(0x11)});
    BOOST_CHECK(decoded.inputs[1].mweb_shared_secret == std::optional<SecretKey>{TestSecret('5')});
    BOOST_CHECK(decoded.inputs[1].mweb_address_descriptor == std::optional<std::string>{"mweb(test)"});
    BOOST_CHECK(decoded.outputs[1].mweb_stealth_address == std::optional<StealthAddress>{TestStealthAddress('7', '8')});
    BOOST_REQUIRE(decoded.outputs[1].mweb_rangeproof.has_value());
    BOOST_CHECK(**decoded.outputs[1].mweb_rangeproof == *TestRangeProof(3));
    BOOST_REQUIRE_EQUAL(decoded.kernels[0].pegouts.size(), 2U);
    BOOST_CHECK(decoded.kernels[0].pegouts[0].GetAmount() == 600);
    BOOST_CHECK(decoded.kernels[0].pegouts[1].GetAmount() == 700);
    BOOST_CHECK(decoded.mweb_tx_offset == std::optional<BlindingFactor>{TestSecret('1')});
    BOOST_CHECK(decoded.mweb_stealth_offset == std::optional<BlindingFactor>{TestSecret('2')});
    BOOST_CHECK(decoded.unknown.count({0xa0}) == 1);
    BOOST_CHECK(decoded.m_proprietary.count(TestProprietary()) == 1);
    BOOST_CHECK(decoded.ContainsMWEBComponents());
}

BOOST_AUTO_TEST_CASE(signed_vectors_roundtrip)
{
    for (const std::string* vec : {&PSBT_MWEB_SIGNED, &PSBT_MWEB_SIGNED_ALT, &PSBT_PEGIN_SIGNED, &PSBT_MIXED_SIGNED, &PSBT_PEGOUT_SIGNED}) {
        BOOST_REQUIRE_MESSAGE(!vec->empty(), "golden vector not yet generated (see psbt_vector_gen)");
        const PartiallySignedTransaction decoded = DecodeHexPSBT(*vec);
        BOOST_CHECK_EQUAL(SerHex(decoded), *vec);
        BOOST_CHECK(decoded.ContainsMWEBComponents());
        BOOST_CHECK(decoded.IsComplete());
        for (unsigned int i = 0; i < decoded.inputs.size(); ++i) {
            if (decoded.inputs[i].IsMWEB()) {
                BOOST_CHECK(PSBTInputSignedAndVerified(decoded, i, nullptr));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(field_subset_roundtrip)
{
    // Clearing any one optional MWEB field must still round-trip: the absence
    // encoding is as load-bearing as the presence encoding. Fields whose
    // removal makes the PSBT structurally invalid (input output_id, output
    // amount, both output identifiers at once) are intentionally not cleared.
    using Clearer = std::function<void(PartiallySignedTransaction&)>;
    const std::vector<Clearer> clearers{
        [](auto& p) { p.inputs[1].mweb_output_commit.reset(); },
        [](auto& p) { p.inputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_input_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_features.reset(); },
        [](auto& p) { p.inputs[1].mweb_sig.reset(); },
        [](auto& p) { p.inputs[1].mweb_amount.reset(); },
        [](auto& p) { p.inputs[1].mweb_shared_secret.reset(); },
        [](auto& p) { p.inputs[1].mweb_key_exchange_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_extra_data.clear(); },
        [](auto& p) { p.inputs[1].mweb_address_descriptor.reset(); },
        [](auto& p) { p.outputs[1].mweb_stealth_address.reset(); }, // mweb_commit still marks it MWEB
        [](auto& p) { p.outputs[1].mweb_commit.reset(); },          // stealth address still marks it MWEB
        [](auto& p) { p.outputs[1].mweb_features.reset(); },
        [](auto& p) { p.outputs[1].mweb_sender_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_extra_data.clear(); },
        [](auto& p) { p.outputs[1].mweb_standard_fields.reset(); },
        [](auto& p) { p.outputs[1].mweb_rangeproof.reset(); },
        [](auto& p) { p.outputs[1].mweb_sig.reset(); },
        [](auto& p) { p.kernels[0].commit.reset(); },
        [](auto& p) { p.kernels[0].stealth_commit.reset(); },
        [](auto& p) { p.kernels[0].fee.reset(); },
        [](auto& p) { p.kernels[0].pegin_amount.reset(); },
        [](auto& p) { p.kernels[0].pegouts.clear(); },
        [](auto& p) { p.kernels[0].lock_height.reset(); },
        [](auto& p) { p.kernels[0].extra_data.clear(); },
        [](auto& p) { p.kernels[0].sig.reset(); },
        [](auto& p) { p.kernels[0].features.reset(); },
        [](auto& p) { p.kernels.clear(); }, // drops the global kernel count entirely
        [](auto& p) { p.mweb_tx_offset.reset(); },
        [](auto& p) { p.mweb_stealth_offset.reset(); },
        [](auto& p) { p.fallback_locktime.reset(); },
        [](auto& p) { p.m_tx_modifiable.reset(); },
    };

    for (size_t i = 0; i < clearers.size(); ++i) {
        PartiallySignedTransaction psbt = AllFieldsPSBT();
        clearers[i](psbt);
        BOOST_TEST_CONTEXT("clearer #" << i) CheckRoundTrip(psbt);
    }
}

// ---------------------------------------------------------------------------
// PSBTv0/v2 gating and decode errors
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v0_rejects_mweb_keytypes)
{
    const std::vector<RawEntry> input_entries{
        Entry(PSBT_IN_MWEB_OUTPUT_ID, Payload(TestHash(1))),
        Entry(PSBT_IN_MWEB_COMMIT, Payload(TestCommitment(1))),
        Entry(PSBT_IN_MWEB_OUTPUT_PUBKEY, Payload(TestPubKey('2'))),
        Entry(PSBT_IN_MWEB_INPUT_PUBKEY, Payload(TestPubKey('3'))),
        Entry(PSBT_IN_MWEB_FEATURES, Payload(uint8_t{1})),
        Entry(PSBT_IN_MWEB_INPUT_SIG, Payload(TestSignature('4'))),
        Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, {'m', 'w', 'e', 'b', '(', 't', ')'}),
        Entry(PSBT_IN_MWEB_AMOUNT, Payload(CAmount{1})),
        Entry(PSBT_IN_MWEB_SHARED_SECRET, Payload(TestSecret('5'))),
        Entry(PSBT_IN_MWEB_KEY_EXCHANGE_PK, Payload(TestPubKey('6'))),
        Entry(PSBT_IN_MWEB_EXTRA_DATA, {0x01}),
    };
    for (const RawEntry& entry : input_entries) {
        BOOST_TEST_CONTEXT("input keytype 0x" << HexStr(Span{entry.first}))
        CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {entry}, {}}), "not allowed in PSBTv0");
    }

    const std::vector<RawEntry> output_entries{
        Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('1', '2'))),
        Entry(PSBT_OUT_MWEB_COMMIT, Payload(TestCommitment(2))),
        Entry(PSBT_OUT_MWEB_FEATURES, Payload(uint8_t{1})),
        Entry(PSBT_OUT_MWEB_SENDER_PUBKEY, Payload(TestPubKey('7'))),
        Entry(PSBT_OUT_MWEB_OUTPUT_PUBKEY, Payload(TestPubKey('8'))),
        Entry(PSBT_OUT_MWEB_STANDARD_FIELDS, Payload(mw::OutputStandardFields(TestPubKey('9'), 1, 2, BigInt<16>::ValueOf(3)))),
        Entry(PSBT_OUT_MWEB_RANGEPROOF, Payload(*TestRangeProof(1))),
        Entry(PSBT_OUT_MWEB_SIG, Payload(TestSignature('a'))),
        Entry(PSBT_OUT_MWEB_EXTRA_DATA, {0x01}),
    };
    for (const RawEntry& entry : output_entries) {
        BOOST_TEST_CONTEXT("output keytype 0x" << HexStr(Span{entry.first}))
        CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {}, {entry}}), "not allowed in PSBTv0");
    }

    // Global MWEB keytypes are collected during parsing and rejected by the
    // post-parse v0 constraint checks.
    RawMap global = V0GlobalMap();
    global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_OFFSET, Payload(TestSecret('1'))));
    CheckDecodeFails(BuildRawPSBT({global, {}, {}}), "PSBT_GLOBAL_MWEB_TX_OFFSET is not allowed in PSBTv0");

    global = V0GlobalMap();
    global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET, Payload(TestSecret('2'))));
    CheckDecodeFails(BuildRawPSBT({global, {}, {}}), "PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET is not allowed in PSBTv0");

    global = V0GlobalMap();
    global.push_back(Entry(PSBT_GLOBAL_MWEB_KERNEL_COUNT, Payload(CompactSizeWriter(1))));
    CheckDecodeFails(BuildRawPSBT({global, {}, {}}), "PSBT_GLOBAL_MWEB_KERNEL_COUNT is not allowed in PSBTv0");
}

BOOST_AUTO_TEST_CASE(v0_serialize_with_mweb_throws)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));
    mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);

    PartiallySignedTransaction psbt(mtx, /*version=*/0);
    psbt.outputs[0].mweb_commit = TestCommitment(1);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_EXCEPTION(ss << psbt, std::ios_base::failure, [](const std::ios_base::failure& e) {
        return std::string(e.what()).find("MWEB fields are not allowed in PSBTv0") != std::string::npos;
    });
}

BOOST_AUTO_TEST_CASE(duplicate_keys_rejected)
{
    // Global map: canonical and MWEB keytypes, unknown, and proprietary.
    {
        RawMap global = V2GlobalMap(0, 0);
        global.push_back(Entry(PSBT_GLOBAL_TX_VERSION, Payload(int32_t{2})));
        CheckDecodeFails(BuildRawPSBT({global}), "Duplicate Key, global transaction version");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_OFFSET, Payload(TestSecret('1'))));
        global.push_back(Entry(PSBT_GLOBAL_MWEB_TX_OFFSET, Payload(TestSecret('2'))));
        CheckDecodeFails(BuildRawPSBT({global}), "Duplicate Key, global MWEB tx offset");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.push_back(Entry(0xa0, {0x01}));
        global.push_back(Entry(0xa0, {0x02}));
        CheckDecodeFails(BuildRawPSBT({global}), "Duplicate Key, key for unknown value");
    }

    // Input map
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_OUTPUT_ID, Payload(TestHash(9))));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Duplicate Key, MWEB output ID");
    }
    {
        RawMap input = V2CanonicalInputMap();
        input.push_back(Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE)));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Duplicate Key, previous txid");
    }
    {
        const PSBTProprietary prop = TestProprietary();
        RawMap input = V2CanonicalInputMap();
        input.emplace_back(prop.key, prop.value);
        input.emplace_back(prop.key, prop.value);
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Duplicate Key, proprietary key");
    }

    // Output map
    {
        RawMap output = V2MWEBOutputMap();
        output.push_back(Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('3', '4'))));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), output}), "Duplicate Key, MWEB stealth address");
    }
    {
        RawMap output = V2CanonicalOutputMap();
        output.push_back(Entry(PSBT_OUT_AMOUNT, Payload(CAmount{2'000})));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), output}), "Duplicate Key, output amount");
    }

    // Kernel map
    {
        RawMap kernel{Entry(PSBT_KERN_FEE, Payload(CAmount{1})), Entry(PSBT_KERN_FEE, Payload(CAmount{2}))};
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), kernel}), "Duplicate Key, kernel fee");
    }
}

BOOST_AUTO_TEST_CASE(unknown_and_proprietary_preserved)
{
    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;
    psbt.unknown[{0xa0}] = {0x01};
    psbt.m_proprietary.insert(TestProprietary("global"));

    PSBTInput input(2);
    input.prev_txid = uint256::ONE;
    input.prev_out = 0;
    input.unknown[{0xa1, 0x02}] = {0x02, 0x03};
    input.m_proprietary.insert(TestProprietary("input"));
    psbt.inputs.push_back(input);

    PSBTOutput output(2);
    output.amount = 1'000;
    output.script = CScript() << OP_TRUE;
    output.unknown[{0xa2}] = {0x04};
    output.m_proprietary.insert(TestProprietary("output"));
    psbt.outputs.push_back(output);

    PSBTKernel kernel;
    kernel.fee = 5;
    kernel.unknown[{0xa3}] = {0x05};
    psbt.kernels.push_back(kernel);

    const std::vector<unsigned char> bytes = Ser(psbt);
    const PartiallySignedTransaction decoded = Deser(bytes);
    BOOST_CHECK_EQUAL(HexStr(bytes), HexStr(Ser(decoded)));
    BOOST_CHECK(decoded.unknown == psbt.unknown);
    BOOST_CHECK(decoded.m_proprietary == psbt.m_proprietary);
    BOOST_CHECK(decoded.inputs[0].unknown == input.unknown);
    BOOST_CHECK(decoded.outputs[0].unknown == output.unknown);
    BOOST_CHECK(decoded.kernels[0].unknown == kernel.unknown);
}

BOOST_AUTO_TEST_CASE(v2_required_fields)
{
    // Missing global requirements
    {
        RawMap global = V2GlobalMap(0, 0);
        global.erase(global.begin()); // drop tx version
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_TX_VERSION is required in PSBTv2");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.erase(global.begin() + 1); // drop input count
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_INPUT_COUNT is required in PSBTv2");
    }
    {
        RawMap global = V2GlobalMap(0, 0);
        global.erase(global.begin() + 2); // drop output count
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_OUTPUT_COUNT is required in PSBTv2");
    }

    // Canonical v2 inputs require the previous outpoint.
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), {Entry(PSBT_IN_OUTPUT_INDEX, Payload(uint32_t{0}))}}),
                     "Previous TXID is required in PSBTv2");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), {Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE))}}),
                     "Previous output's index is required in PSBTv2");

    // MWEB inputs are exempt from the previous-outpoint requirement.
    const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(1, 1), V2MWEBInputMap(), V2MWEBOutputMap()}));
    BOOST_CHECK(psbt.inputs[0].IsMWEB());

    // v2 outputs require an amount, and a script unless MWEB.
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), {Entry(PSBT_OUT_MWEB_STEALTH_ADDRESS, Payload(TestStealthAddress('1', '2')))}}),
                     "Output amount is required in PSBTv2");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 1), {Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1'000}))}}),
                     "Output script is required in PSBTv2");
}

BOOST_AUTO_TEST_CASE(version_gating)
{
    // v2-only global keys inside a v0 PSBT
    for (const auto& [entry, error] : std::vector<std::pair<RawEntry, std::string>>{
             {Entry(PSBT_GLOBAL_TX_VERSION, Payload(int32_t{2})), "PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_FALLBACK_LOCKTIME, Payload(uint32_t{100})), "PSBT_GLOBAL_FALLBACK_LOCKTIME is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_INPUT_COUNT, Payload(CompactSizeWriter(1))), "PSBT_GLOBAL_INPUT_COUNT is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_OUTPUT_COUNT, Payload(CompactSizeWriter(1))), "PSBT_GLOBAL_OUTPUT_COUNT is not allowed in PSBTv0"},
             {Entry(PSBT_GLOBAL_TX_MODIFIABLE, Payload(uint8_t{1})), "PSBT_GLOBAL_TX_MODIFIABLE is not allowed in PSBTv0"},
         }) {
        RawMap global = V0GlobalMap();
        global.push_back(entry);
        BOOST_TEST_CONTEXT(error) CheckDecodeFails(BuildRawPSBT({global, {}, {}}), error);
    }

    // v0-only global unsigned tx inside a v2 PSBT
    {
        RawMap global = V2GlobalMap(0, 0);
        global.insert(global.begin(), V0GlobalMap()[0]);
        CheckDecodeFails(BuildRawPSBT({global}), "PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2");
    }

    // v2-only input/output keys inside a v0 PSBT
    {
        CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {Entry(PSBT_IN_PREVIOUS_TXID, Payload(uint256::ONE))}, {}}),
                         "Previous txid is not allowed in PSBTv0");
        CheckDecodeFails(BuildRawPSBT({V0GlobalMap(), {}, {Entry(PSBT_OUT_AMOUNT, Payload(CAmount{1}))}}),
                         "Output amount is not allowed in PSBTv0");
    }

    // Version 1 does not exist; versions above the highest supported fail at parse time.
    CheckDecodeFails(BuildRawPSBT({{Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{1}))}}), "There is no PSBT version 1");
    CheckDecodeFails(BuildRawPSBT({{Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{3}))}}), "Unsupported version number");
}

BOOST_AUTO_TEST_CASE(mweb_ordering_enforced)
{
    // Canonical input serialized after an MWEB input
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(2, 0), V2MWEBInputMap(), V2CanonicalInputMap()}),
                     "MWEB inputs must be last");
    // Canonical output serialized after an MWEB output
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 2), V2MWEBOutputMap(), V2CanonicalOutputMap()}),
                     "MWEB outputs must be last");
    // The canonical-first orderings decode fine.
    CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(2, 2), V2CanonicalInputMap(), V2MWEBInputMap(), V2CanonicalOutputMap(), V2MWEBOutputMap()}));

    // Declared counts must match the maps present.
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(2, 0), V2CanonicalInputMap()}),
                     "Inputs provided does not match the number of inputs in transaction");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 2), V2CanonicalInputMap(), V2CanonicalOutputMap()}),
                     "Outputs provided does not match the number of outputs in transaction");
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 1, 2), V2CanonicalInputMap(), V2CanonicalOutputMap(), {Entry(PSBT_KERN_FEE, Payload(CAmount{1}))}}),
                     "Kernels provided does not match the number of kernels in transaction");
}

BOOST_AUTO_TEST_CASE(kernel_pegout_encoding)
{
    const CScript script = CScript() << OP_TRUE;
    const auto pegout_entry = [&](uint64_t index, CAmount amount) {
        return Entry(PSBT_KERN_PEGOUT, Payload(amount, script), Payload(CompactSizeWriter(index)));
    };

    // Two pegouts round-trip in index order even when serialized out of order.
    {
        const RawMap kernel{pegout_entry(1, 700), pegout_entry(0, 600)};
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(0, 0, 1), kernel}));
        BOOST_REQUIRE_EQUAL(psbt.kernels[0].pegouts.size(), 2U);
        BOOST_CHECK_EQUAL(psbt.kernels[0].pegouts[0].GetAmount(), 600);
        BOOST_CHECK_EQUAL(psbt.kernels[0].pegouts[1].GetAmount(), 700);
        CheckRoundTrip(psbt);
    }

    // Non-contiguous indexes
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {pegout_entry(0, 600), pegout_entry(2, 700)}}),
                     "Kernel pegout indexes must be contiguous");
    // Exact duplicate key
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {pegout_entry(0, 600), pegout_entry(0, 600)}}),
                     "Duplicate Key, pegout is already provided");
    // Key without an index
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {Entry(PSBT_KERN_PEGOUT, Payload(CAmount{600}, script))}}),
                     "Kernel pegout key is missing index");
    // Key with trailing bytes after the index
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {Entry(PSBT_KERN_PEGOUT, Payload(CAmount{600}, script), {0x00, 0xff})}}),
                     "Kernel pegout key has unexpected data after index");
    // Empty pegout script (mirrors PegOutCoin's own deserialization check)
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(0, 0, 1), {Entry(PSBT_KERN_PEGOUT, Payload(CAmount{600}, CScript()), Payload(CompactSizeWriter(0)))}}),
                     "Pegout scriptPubKey must not be empty");
}

BOOST_AUTO_TEST_CASE(decode_api_errors)
{
    PartiallySignedTransaction psbt;
    std::string error;

    BOOST_CHECK(!DecodeBase64PSBT(psbt, "this is not base64!!!", error));
    BOOST_CHECK_EQUAL(error, "invalid base64");

    // Wrong magic
    std::vector<unsigned char> raw{'p', 's', 'b', 't', 0x00};
    CheckDecodeFails(raw, "Invalid PSBT magic bytes");

    // Trailing bytes after a valid PSBT
    std::vector<unsigned char> with_trailing = BuildRawPSBT({V2GlobalMap(0, 0)});
    with_trailing.push_back(0x00);
    CheckDecodeFails(with_trailing, "extra data after PSBT");

    // Truncation mid-stream
    std::vector<unsigned char> truncated = BuildRawPSBT({V2GlobalMap(0, 0)});
    truncated.resize(truncated.size() / 2);
    BOOST_CHECK(!DecodeRawPSBT(psbt, MakeByteSpan(truncated), error));
    BOOST_CHECK(!error.empty());

    // Missing global separator
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << PSBT_MAGIC_BYTES;
        const RawEntry entry = Entry(PSBT_GLOBAL_VERSION, Payload(uint32_t{2}));
        s << entry.first << entry.second;
        CheckDecodeFails(ToBytes(s), "Separator is missing at the end of the global map");
    }
    // Missing input-map separator
    {
        std::vector<unsigned char> bytes = BuildRawPSBT({V2GlobalMap(1, 0), V2CanonicalInputMap()});
        bytes.pop_back(); // strip the input map's separator
        CheckDecodeFails(bytes, "Separator is missing at the end of an input map");
    }
}

BOOST_AUTO_TEST_CASE(mweb_addr_descriptor_validation)
{
    // Backward compatibility: a 4-byte value for key 0x96 (the pre-descriptor
    // MWEB address index encoding) is silently ignored.
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, {0x01, 0x00, 0x00, 0x00}));
        const PartiallySignedTransaction psbt = CheckDecodeSucceeds(BuildRawPSBT({V2GlobalMap(1, 0), input}));
        BOOST_CHECK(!psbt.inputs[0].mweb_address_descriptor.has_value());
    }
    // Anything else must be an ASCII mweb() descriptor.
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, {'w', 'p', 'k', 'h', '(', 'x', ')'}));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "MWEB address descriptor must be an ASCII mweb() descriptor");
    }
    {
        RawMap input = V2MWEBInputMap();
        input.push_back(Entry(PSBT_IN_MWEB_ADDR_DESCRIPTOR, {'m', 'w', 'e', 'b', '(', 0xff, ')'}));
        CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "MWEB address descriptor must be an ASCII mweb() descriptor");
    }
}

BOOST_AUTO_TEST_CASE(mweb_input_triplet_without_output_id)
{
    // PSBT_IN_MWEB_OUTPUT_ID is what marks an input map as MWEB (see
    // doc/mweb/psbt-mweb.md section 3.1). An input carrying only the
    // commitment/pubkey fields is treated as a canonical input and rejected
    // by the PSBTv2 previous-outpoint requirement.
    const RawMap input{
        Entry(PSBT_IN_MWEB_COMMIT, Payload(TestCommitment(1))),
        Entry(PSBT_IN_MWEB_OUTPUT_PUBKEY, Payload(TestPubKey('2'))),
        Entry(PSBT_IN_MWEB_INPUT_PUBKEY, Payload(TestPubKey('3'))),
    };
    CheckDecodeFails(BuildRawPSBT({V2GlobalMap(1, 0), input}), "Previous TXID is required in PSBTv2");
}

// ---------------------------------------------------------------------------
// BIP-174/BIP-370/BIP-371 vectors
// ---------------------------------------------------------------------------
// Source: test/functional/data/rpc_psbt.json (snapshotted to
// src/test/data/rpc_psbt.json), originally the BIP-174/370/371 test vectors
// adjusted for this fork's PSBTv2+MWEB-aware parser. The functional test
// rpc_psbt.py runs the same file through the RPC layer; here the vectors are
// exercised directly against the decoder, with the added requirement that
// re-serialization is stable (idempotent after one normalization pass).

namespace {
UniValue ReadPSBTJson()
{
    UniValue doc;
    const std::string json(json_tests::rpc_psbt, json_tests::rpc_psbt + sizeof(json_tests::rpc_psbt));
    BOOST_REQUIRE(doc.read(json));
    BOOST_REQUIRE(doc.isObject());
    return doc;
}
} // namespace

BOOST_AUTO_TEST_CASE(bip174_invalid_vectors)
{
    const UniValue doc = ReadPSBTJson();
    const UniValue& invalid = doc["invalid"];
    BOOST_REQUIRE(invalid.isArray());
    BOOST_REQUIRE(invalid.size() > 0);

    for (size_t i = 0; i < invalid.size(); ++i) {
        PartiallySignedTransaction psbt;
        std::string error;
        BOOST_TEST_CONTEXT("invalid[" << i << "]")
        BOOST_CHECK(!DecodeBase64PSBT(psbt, invalid[i].get_str(), error));
    }

    const UniValue& invalid_with_msg = doc["invalid_with_msg"];
    BOOST_REQUIRE(invalid_with_msg.isArray());
    for (size_t i = 0; i < invalid_with_msg.size(); ++i) {
        PartiallySignedTransaction psbt;
        std::string error;
        BOOST_TEST_CONTEXT("invalid_with_msg[" << i << "]")
        {
            BOOST_CHECK(!DecodeBase64PSBT(psbt, invalid_with_msg[i][0].get_str(), error));
            // ios_base::failure::what() appends ": iostream error"; match the prefix.
            BOOST_CHECK_MESSAGE(error.rfind(invalid_with_msg[i][1].get_str(), 0) == 0,
                                "error was \"" + error + "\", expected prefix \"" + invalid_with_msg[i][1].get_str() + "\"");
        }
    }
}

BOOST_AUTO_TEST_CASE(bip174_valid_vectors)
{
    const UniValue doc = ReadPSBTJson();
    const UniValue& valid = doc["valid"];
    BOOST_REQUIRE(valid.isArray());
    BOOST_REQUIRE(valid.size() > 0);

    for (size_t i = 0; i < valid.size(); ++i) {
        BOOST_TEST_CONTEXT("valid[" << i << "]")
        {
            PartiallySignedTransaction psbt;
            std::string error;
            BOOST_REQUIRE_MESSAGE(DecodeBase64PSBT(psbt, valid[i].get_str(), error), error);

            // Serialization normalizes some encodings (witness data is
            // stripped from non_witness_utxo transactions; an explicit
            // version-0 global key is dropped), so byte-identity with the
            // original cannot hold for every vector. Require idempotence
            // instead: the normalized form must decode and re-serialize
            // byte-identically.
            const std::vector<unsigned char> normalized = Ser(psbt);
            const PartiallySignedTransaction redecoded = Deser(normalized);
            BOOST_CHECK_EQUAL(HexStr(Ser(redecoded)), HexStr(normalized));
        }
    }
}

// ---------------------------------------------------------------------------
// Structure and utility functions
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(get_unsigned_tx_mapping)
{
    const PartiallySignedTransaction psbt = AllFieldsPSBT();
    const CMutableTransaction mtx = psbt.GetUnsignedTx();

    BOOST_REQUIRE_EQUAL(mtx.vin.size(), 1U);
    BOOST_CHECK(mtx.vin[0].prevout == COutPoint(uint256::ONE, 0));
    BOOST_CHECK_EQUAL(mtx.vin[0].nSequence, 0xfffffffe);
    BOOST_REQUIRE_EQUAL(mtx.vout.size(), 1U);
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, 50'000);

    BOOST_REQUIRE_EQUAL(mtx.mweb_tx.inputs.size(), 1U);
    const mw::MutableInput& mweb_in = mtx.mweb_tx.inputs[0];
    BOOST_CHECK(mweb_in.output_id == TestHash(0x11));
    BOOST_CHECK(mweb_in.commitment == std::optional<Commitment>{TestCommitment(1)});
    BOOST_CHECK(mweb_in.output_pubkey == std::optional<PublicKey>{TestPubKey('2')});
    BOOST_CHECK(mweb_in.input_pubkey == std::optional<PublicKey>{TestPubKey('3')});
    BOOST_CHECK(mweb_in.amount == std::optional<CAmount>{12345});
    BOOST_CHECK(mweb_in.features == std::optional<uint8_t>{0x03});
    BOOST_CHECK(mweb_in.signature == std::optional<Signature>{TestSignature('4')});
    BOOST_CHECK(mweb_in.key_exchange_pubkey == std::optional<PublicKey>{TestPubKey('6')});
    BOOST_CHECK(mweb_in.shared_secret == std::optional<SecretKey>{TestSecret('5')});
    // The shared secret also implies the pre-switch blinding factor.
    BOOST_CHECK(mweb_in.raw_blind == std::optional<BlindingFactor>{mw::DeriveOutputRawBlind(TestSecret('5'))});

    BOOST_REQUIRE_EQUAL(mtx.mweb_tx.outputs.size(), 1U);
    const mw::MutableOutput& mweb_out = mtx.mweb_tx.outputs[0];
    BOOST_CHECK(mweb_out.commitment == std::optional<Commitment>{TestCommitment(2)});
    BOOST_CHECK(mweb_out.sender_pubkey == std::optional<PublicKey>{TestPubKey('9')});
    BOOST_CHECK(mweb_out.receiver_pubkey == std::optional<PublicKey>{TestPubKey('a')});
    BOOST_CHECK(mweb_out.amount == std::optional<CAmount>{90'000});
    BOOST_CHECK(mweb_out.address == std::optional<StealthAddress>{TestStealthAddress('7', '8')});
    BOOST_REQUIRE(mweb_out.message.has_value());
    BOOST_CHECK_EQUAL(mweb_out.message->features, 0x03);
    BOOST_CHECK(mweb_out.message->standard_fields.has_value());
    BOOST_CHECK(mweb_out.signature == std::optional<Signature>{TestSignature('d')});

    BOOST_REQUIRE_EQUAL(mtx.mweb_tx.kernels.size(), 1U);
    const mw::MutableKernel& kernel = mtx.mweb_tx.kernels[0];
    BOOST_CHECK(kernel.fee == std::optional<CAmount>{1'000});
    BOOST_CHECK(kernel.pegin == std::optional<CAmount>{5'000});
    BOOST_REQUIRE_EQUAL(kernel.GetPegOuts().size(), 2U);
    BOOST_CHECK(kernel.GetPegOuts()[0].GetAmount() == 600);
    BOOST_CHECK(kernel.lock_height == std::optional<int32_t>{123});
    BOOST_CHECK(kernel.excess == std::optional<Commitment>{TestCommitment(4)});
    BOOST_CHECK(kernel.stealth_excess == std::optional<PublicKey>{TestPubKey('e')});
    BOOST_CHECK(kernel.signature == std::optional<Signature>{TestSignature('f')});

    BOOST_CHECK(mtx.mweb_tx.kernel_offset == BlindingFactor{TestSecret('1')});
    BOOST_CHECK(mtx.mweb_tx.stealth_offset == BlindingFactor{TestSecret('2')});

    // A missing sequence defaults to SEQUENCE_FINAL.
    {
        PartiallySignedTransaction seq_psbt;
        seq_psbt.m_psbt_version = 2;
        seq_psbt.tx_version = 2;
        PSBTInput in(2);
        in.prev_txid = uint256::ONE;
        in.prev_out = 0;
        seq_psbt.inputs.push_back(in);
        BOOST_CHECK_EQUAL(seq_psbt.GetUnsignedTx().vin[0].nSequence, uint32_t{CTxIn::SEQUENCE_FINAL});
    }

    // The v0 path returns the stored global transaction untouched.
    {
        CMutableTransaction v0_mtx;
        v0_mtx.nVersion = 2;
        v0_mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));
        v0_mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);
        const PartiallySignedTransaction v0_psbt(v0_mtx, 0);
        BOOST_CHECK(v0_psbt.GetUnsignedTx().GetHash() == v0_mtx.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(get_unique_id_semantics)
{
    // v2: the unique ID is invariant under sequence changes.
    {
        PartiallySignedTransaction psbt = AllFieldsPSBT();
        const uint256 id = psbt.GetUniqueID();
        psbt.inputs[0].sequence = 1;
        BOOST_CHECK(psbt.GetUniqueID() == id);
    }

    // Two MWEB PSBTs differing only in MWEB payload share a unique ID: the
    // canonical txid does not commit to MWEB data. This is why
    // PartiallySignedTransaction::Merge compares MWEB PSBTs structurally
    // instead of by unique ID.
    {
        PartiallySignedTransaction a = AllFieldsPSBT();
        PartiallySignedTransaction b = AllFieldsPSBT();
        b.kernels[0].sig = TestSignature('0');
        b.outputs[1].mweb_commit = TestCommitment(99);
        BOOST_CHECK(a.GetUniqueID() == b.GetUniqueID());

        // A canonical difference does change the ID.
        PartiallySignedTransaction c = AllFieldsPSBT();
        c.outputs[0].amount = 60'000;
        BOOST_CHECK(a.GetUniqueID() != c.GetUniqueID());
    }

    // v0: the unique ID is the unsigned transaction's hash.
    {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));
        mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);
        const PartiallySignedTransaction psbt(mtx, 0);
        BOOST_CHECK(psbt.GetUniqueID() == mtx.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(setup_from_tx_mapping)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 555;
    mtx.vin.emplace_back(COutPoint(uint256::ONE, 3));
    mtx.vin[0].nSequence = 0xfffffffd;
    mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);

    mw::MutableInput mweb_in(TestHash(0x21));
    mweb_in.commitment = TestCommitment(1);
    mweb_in.output_pubkey = TestPubKey('2');
    mweb_in.input_pubkey = TestPubKey('3');
    mweb_in.features = 1;
    mweb_in.signature = TestSignature('4');
    mweb_in.amount = 777;
    mweb_in.extradata = {0x01};
    mtx.mweb_tx.inputs.push_back(mweb_in);

    mw::MutableOutput mweb_out;
    mweb_out.amount = 888;
    mweb_out.address = TestStealthAddress('5', '6');
    mweb_out.commitment = TestCommitment(2);
    mweb_out.sender_pubkey = TestPubKey('7');
    mweb_out.receiver_pubkey = TestPubKey('8');
    mweb_out.message = mw::OutputMessage(mw::OutputMessage::EXTRA_DATA_FEATURE_BIT, std::nullopt, {0x02});
    mweb_out.proof = TestRangeProof(9);
    mweb_out.signature = TestSignature('a');
    mtx.mweb_tx.outputs.push_back(mweb_out);

    mw::MutableKernel kernel;
    kernel.fee = 10;
    kernel.pegin = 20;
    kernel.SetPegOuts({PegOutCoin(30, CScript() << OP_TRUE)});
    kernel.lock_height = 40;
    kernel.stealth_excess = TestPubKey('b');
    kernel.extradata = {0x03};
    kernel.excess = TestCommitment(3);
    kernel.signature = TestSignature('c');
    mtx.mweb_tx.kernels.push_back(kernel);

    mtx.mweb_tx.kernel_offset = TestSecret('d');
    mtx.mweb_tx.stealth_offset = TestSecret('e');

    const PartiallySignedTransaction psbt(mtx, 2);

    BOOST_REQUIRE_EQUAL(psbt.inputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(psbt.outputs.size(), 2U);
    BOOST_REQUIRE_EQUAL(psbt.kernels.size(), 1U);
    BOOST_CHECK(psbt.fallback_locktime == std::optional<uint32_t>{555});

    BOOST_CHECK(psbt.inputs[0].prev_txid == uint256::ONE);
    BOOST_CHECK(psbt.inputs[0].prev_out == std::optional<uint32_t>{3});
    BOOST_CHECK(psbt.inputs[0].sequence == std::optional<uint32_t>{0xfffffffd});

    BOOST_CHECK(psbt.inputs[1].mweb_output_id == std::optional<mw::Hash>{TestHash(0x21)});
    BOOST_CHECK(psbt.inputs[1].mweb_output_commit == mweb_in.commitment);
    BOOST_CHECK(psbt.inputs[1].mweb_output_pubkey == mweb_in.output_pubkey);
    BOOST_CHECK(psbt.inputs[1].mweb_input_pubkey == mweb_in.input_pubkey);
    BOOST_CHECK(psbt.inputs[1].mweb_features == mweb_in.features);
    BOOST_CHECK(psbt.inputs[1].mweb_sig == mweb_in.signature);
    BOOST_CHECK(psbt.inputs[1].mweb_amount == mweb_in.amount);
    BOOST_CHECK(psbt.inputs[1].mweb_extra_data == mweb_in.extradata);

    BOOST_CHECK(psbt.outputs[0].amount == std::optional<CAmount>{1'000});
    BOOST_CHECK(psbt.outputs[1].amount == std::optional<CAmount>{888});
    BOOST_CHECK(psbt.outputs[1].mweb_stealth_address == mweb_out.address);
    BOOST_CHECK(psbt.outputs[1].mweb_commit == mweb_out.commitment);
    BOOST_CHECK(psbt.outputs[1].mweb_features == std::optional<uint8_t>{mw::OutputMessage::EXTRA_DATA_FEATURE_BIT});
    BOOST_CHECK(psbt.outputs[1].mweb_sender_pubkey == mweb_out.sender_pubkey);
    BOOST_CHECK(psbt.outputs[1].mweb_output_pubkey == mweb_out.receiver_pubkey);
    BOOST_CHECK(psbt.outputs[1].mweb_extra_data == std::vector<uint8_t>{0x02});
    BOOST_CHECK(psbt.outputs[1].mweb_rangeproof == mweb_out.proof);
    BOOST_CHECK(psbt.outputs[1].mweb_sig == mweb_out.signature);

    BOOST_CHECK(psbt.kernels[0].features == std::optional<uint8_t>{kernel.CalcFeatureByte()});
    BOOST_CHECK(psbt.kernels[0].commit == kernel.excess);
    BOOST_CHECK(psbt.kernels[0].stealth_commit == kernel.stealth_excess);
    BOOST_CHECK(psbt.kernels[0].fee == kernel.fee);
    BOOST_CHECK(psbt.kernels[0].pegin_amount == kernel.pegin);
    BOOST_CHECK(psbt.kernels[0].pegouts == kernel.GetPegOuts());
    BOOST_CHECK(psbt.kernels[0].lock_height == kernel.lock_height);
    BOOST_CHECK(psbt.kernels[0].extra_data == kernel.extradata);
    BOOST_CHECK(psbt.kernels[0].sig == kernel.signature);

    BOOST_CHECK(psbt.mweb_tx_offset == std::optional<BlindingFactor>{TestSecret('d')});
    BOOST_CHECK(psbt.mweb_stealth_offset == std::optional<BlindingFactor>{TestSecret('e')});
}

BOOST_AUTO_TEST_CASE(compute_timelock)
{
    const auto make_psbt = [](std::optional<uint32_t> fallback = std::nullopt) {
        PartiallySignedTransaction psbt;
        psbt.m_psbt_version = 2;
        psbt.tx_version = 2;
        psbt.fallback_locktime = fallback;
        return psbt;
    };
    const auto locked_input = [](std::optional<uint32_t> time_lock, std::optional<uint32_t> height_lock) {
        PSBTInput input(2);
        input.prev_txid = uint256::ONE;
        input.prev_out = 0;
        input.time_locktime = time_lock;
        input.height_locktime = height_lock;
        return input;
    };

    uint32_t locktime;

    // Pure height locks: the maximum wins.
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(std::nullopt, 100));
        psbt.inputs.push_back(locked_input(std::nullopt, 200));
        BOOST_REQUIRE(psbt.ComputeTimeLock(locktime));
        BOOST_CHECK_EQUAL(locktime, 200U);
    }
    // Pure time locks: the maximum wins.
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(500'000'100, std::nullopt));
        psbt.inputs.push_back(locked_input(500'000'200, std::nullopt));
        BOOST_REQUIRE(psbt.ComputeTimeLock(locktime));
        BOOST_CHECK_EQUAL(locktime, 500'000'200U);
    }
    // Height is preferred when every input allows both.
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(500'000'100, 100));
        psbt.inputs.push_back(locked_input(std::nullopt, 200));
        BOOST_REQUIRE(psbt.ComputeTimeLock(locktime));
        BOOST_CHECK_EQUAL(locktime, 200U);
    }
    // Conflicting requirements: one input requires time-only, another height-only.
    {
        PartiallySignedTransaction psbt = make_psbt();
        psbt.inputs.push_back(locked_input(500'000'100, std::nullopt));
        psbt.inputs.push_back(locked_input(std::nullopt, 200));
        BOOST_CHECK(!psbt.ComputeTimeLock(locktime));
    }
    // No locks: fallback applies.
    {
        PartiallySignedTransaction psbt = make_psbt(777);
        psbt.inputs.push_back(locked_input(std::nullopt, std::nullopt));
        BOOST_REQUIRE(psbt.ComputeTimeLock(locktime));
        BOOST_CHECK_EQUAL(locktime, 777U);
    }
    // No locks, no fallback: zero.
    {
        PartiallySignedTransaction psbt = make_psbt();
        BOOST_REQUIRE(psbt.ComputeTimeLock(locktime));
        BOOST_CHECK_EQUAL(locktime, 0U);
    }
}

BOOST_AUTO_TEST_CASE(add_input_rules)
{
    const auto v2_input = [](const uint256& txid, uint32_t vout) {
        PSBTInput input(2);
        input.prev_txid = txid;
        input.prev_out = vout;
        return input;
    };

    // v0: duplicate outpoints are rejected; existing signatures are cleared on add.
    {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));
        mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);
        PartiallySignedTransaction psbt(mtx, 0);

        PSBTInput dup(0);
        dup.prev_txid = uint256::ONE;
        dup.prev_out = 0;
        BOOST_CHECK(!psbt.AddInput(dup));

        PSBTInput fresh(0);
        fresh.prev_txid = uint256::ONE;
        fresh.prev_out = 1;
        fresh.partial_sigs.emplace(CKeyID(), SigPair(CPubKey(), std::vector<unsigned char>{0x30}));
        fresh.final_script_sig = CScript() << OP_TRUE;
        BOOST_CHECK(psbt.AddInput(fresh));
        BOOST_CHECK(psbt.inputs.back().partial_sigs.empty());
        BOOST_CHECK(psbt.inputs.back().final_script_sig.empty());
        BOOST_CHECK_EQUAL(psbt.tx->vin.size(), 2U);
    }

    // v2 rules
    {
        PartiallySignedTransaction psbt;
        psbt.m_psbt_version = 2;
        psbt.tx_version = 2;

        // Missing prev fields
        PSBTInput no_prev(2);
        BOOST_CHECK(!psbt.AddInput(no_prev));

        // Inputs-modifiable flag must be present and set
        PSBTInput input = v2_input(uint256::ONE, 0);
        BOOST_CHECK(!psbt.AddInput(input)); // m_tx_modifiable absent
        psbt.m_tx_modifiable = std::bitset<8>{0x02};
        BOOST_CHECK(!psbt.AddInput(input)); // bit 0 clear
        psbt.m_tx_modifiable = std::bitset<8>{0x01};
        BOOST_CHECK(psbt.AddInput(input));

        // Duplicates rejected
        PSBTInput dup = v2_input(uint256::ONE, 0);
        BOOST_CHECK(!psbt.AddInput(dup));

        // Adding a locktime-bearing input that changes the effective locktime
        // is rejected once another input carries partial signatures.
        psbt.inputs[0].partial_sigs.emplace(CKeyID(), SigPair(CPubKey(), std::vector<unsigned char>{0x30}));
        PSBTInput locked = v2_input(uint256::ONE, 1);
        locked.height_locktime = 500;
        BOOST_CHECK(!psbt.AddInput(locked));

        // Without signatures the same input is accepted.
        psbt.inputs[0].partial_sigs.clear();
        BOOST_CHECK(psbt.AddInput(locked));
    }
}

BOOST_AUTO_TEST_CASE(add_output_rules)
{
    PSBTOutput valid(2);
    valid.amount = 1'000;
    valid.script = CScript() << OP_TRUE;

    PSBTOutput no_amount(2);
    no_amount.script = CScript() << OP_TRUE;

    PSBTOutput no_script(2);
    no_script.amount = 1'000;

    // v0 appends to the global transaction.
    {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));
        mtx.vout.emplace_back(1'000, CScript() << OP_TRUE);
        PartiallySignedTransaction psbt(mtx, 0);
        BOOST_CHECK(!psbt.AddOutput(no_amount));
        BOOST_CHECK(!psbt.AddOutput(no_script));
        BOOST_CHECK(psbt.AddOutput(valid));
        BOOST_CHECK_EQUAL(psbt.tx->vout.size(), 2U);
    }

    // v2 requires the outputs-modifiable bit.
    {
        PartiallySignedTransaction psbt;
        psbt.m_psbt_version = 2;
        psbt.tx_version = 2;
        BOOST_CHECK(!psbt.AddOutput(valid)); // m_tx_modifiable absent
        psbt.m_tx_modifiable = std::bitset<8>{0x01};
        BOOST_CHECK(!psbt.AddOutput(valid)); // bit 1 clear
        psbt.m_tx_modifiable = std::bitset<8>{0x02};
        BOOST_CHECK(psbt.AddOutput(valid));
        BOOST_CHECK_EQUAL(psbt.outputs.size(), 1U);
    }
}

BOOST_AUTO_TEST_CASE(is_complete_mweb_requirements)
{
    BOOST_REQUIRE(PresenceCompletePSBT().IsComplete());

    // Each requirement, removed in isolation, must flip IsComplete() to false.
    using Breaker = std::function<void(PartiallySignedTransaction&)>;
    const std::vector<Breaker> breakers{
        // canonical input unsigned
        [](auto& p) { p.inputs[0].final_script_witness.SetNull(); },
        // MWEB input requirements
        [](auto& p) { p.inputs[1].mweb_sig.reset(); },
        [](auto& p) { p.inputs[1].mweb_features.reset(); },
        [](auto& p) { p.inputs[1].mweb_output_commit.reset(); },
        [](auto& p) { p.inputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.inputs[1].mweb_input_pubkey.reset(); }, // stealth-key feature bit set
        [](auto& p) { p.inputs[1].mweb_extra_data.clear(); },   // extra-data feature bit set
        // kernel requirements
        [](auto& p) { p.kernels.clear(); },
        [](auto& p) { p.kernels[0].commit.reset(); },
        [](auto& p) { p.kernels[0].features.reset(); },
        [](auto& p) { p.kernels[0].sig.reset(); },
        [](auto& p) { p.kernels[0].fee.reset(); },
        [](auto& p) { p.kernels[0].pegin_amount.reset(); },
        [](auto& p) { p.kernels[0].pegouts.clear(); },
        [](auto& p) { p.kernels[0].lock_height.reset(); },
        [](auto& p) { p.kernels[0].stealth_commit.reset(); },
        [](auto& p) { p.kernels[0].extra_data.clear(); },
        // MWEB output requirements
        [](auto& p) { p.outputs[1].mweb_commit.reset(); },
        [](auto& p) { p.outputs[1].mweb_features.reset(); },
        [](auto& p) { p.outputs[1].mweb_sender_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_output_pubkey.reset(); },
        [](auto& p) { p.outputs[1].mweb_rangeproof.reset(); },
        [](auto& p) { p.outputs[1].mweb_sig.reset(); },
        [](auto& p) { p.outputs[1].mweb_standard_fields.reset(); }, // standard-fields feature bit set
        [](auto& p) { p.outputs[1].mweb_extra_data.clear(); },      // extra-data feature bit set
        // global offsets
        [](auto& p) { p.mweb_tx_offset.reset(); },
        [](auto& p) { p.mweb_stealth_offset.reset(); },
    };

    for (size_t i = 0; i < breakers.size(); ++i) {
        PartiallySignedTransaction psbt = PresenceCompletePSBT();
        breakers[i](psbt);
        BOOST_CHECK_MESSAGE(!psbt.IsComplete(), "breaker #" << i << " did not invalidate completeness");
    }

    // A clearer whose field is not load-bearing (e.g. output stealth address
    // once the commitment is present) must NOT flip completeness.
    PartiallySignedTransaction psbt = PresenceCompletePSBT();
    psbt.outputs[1].mweb_stealth_address.reset();
    BOOST_CHECK(psbt.IsComplete());
}

BOOST_AUTO_TEST_CASE(count_unsigned_inputs)
{
    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;

    PSBTInput script_sig(2);
    script_sig.final_script_sig = CScript() << OP_TRUE;
    psbt.inputs.push_back(script_sig);

    PSBTInput witness(2);
    witness.final_script_witness.stack.push_back({0x01});
    psbt.inputs.push_back(witness);

    PSBTInput mweb = MWEBInput(TestHash(1));
    mweb.mweb_sig = TestSignature('1');
    psbt.inputs.push_back(mweb);

    psbt.inputs.emplace_back(2); // unsigned

    BOOST_CHECK_EQUAL(CountPSBTUnsignedInputs(psbt), 1U);
}

BOOST_AUTO_TEST_CASE(remove_unnecessary_transactions)
{
    const CScript taproot_script = CScript() << OP_1 << std::vector<unsigned char>(32, 0x01);
    const CScript segwit_v0_script = CScript() << OP_0 << std::vector<unsigned char>(20, 0x01);

    CMutableTransaction prev;
    prev.vout.emplace_back(1'000, taproot_script);
    const CTransactionRef prev_ref = MakeTransactionRef(prev);

    const auto make_input = [&](const CScript& spk) {
        PSBTInput input(2);
        input.prev_txid = prev_ref->GetHash();
        input.prev_out = 0;
        input.witness_utxo = CTxOut(1'000, spk);
        input.non_witness_utxo = prev_ref;
        return input;
    };
    const auto make_psbt = [&](const CScript& second_spk) {
        PartiallySignedTransaction psbt;
        psbt.m_psbt_version = 2;
        psbt.tx_version = 2;
        psbt.inputs.push_back(make_input(taproot_script));
        psbt.inputs.push_back(make_input(second_spk));
        return psbt;
    };

    // All-taproot: previous transactions are dropped.
    {
        PartiallySignedTransaction psbt = make_psbt(taproot_script);
        RemoveUnnecessaryTransactions(psbt, SIGHASH_ALL);
        BOOST_CHECK(!psbt.inputs[0].non_witness_utxo);
        BOOST_CHECK(!psbt.inputs[1].non_witness_utxo);
    }
    // Any segwit v0 input: nothing is dropped.
    {
        PartiallySignedTransaction psbt = make_psbt(segwit_v0_script);
        RemoveUnnecessaryTransactions(psbt, SIGHASH_ALL);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
        BOOST_CHECK(psbt.inputs[1].non_witness_utxo);
    }
    // Any input without a witness UTXO: nothing is dropped.
    {
        PartiallySignedTransaction psbt = make_psbt(taproot_script);
        psbt.inputs[1].witness_utxo.SetNull();
        RemoveUnnecessaryTransactions(psbt, SIGHASH_ALL);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
    }
    // SIGHASH_ANYONECANPAY: nothing is dropped.
    {
        PartiallySignedTransaction psbt = make_psbt(taproot_script);
        RemoveUnnecessaryTransactions(psbt, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
        BOOST_CHECK(psbt.inputs[0].non_witness_utxo);
        BOOST_CHECK(psbt.inputs[1].non_witness_utxo);
    }
}

BOOST_AUTO_TEST_CASE(update_psbt_output)
{
    const CKey key = ToCKey(TestSecret('7'));
    const CPubKey pubkey = key.GetPubKey();

    FlatSigningProvider provider;
    provider.pubkeys.emplace(pubkey.GetID(), pubkey);
    KeyOriginInfo origin{};
    origin.hdkeypath.path = {0x80000000};
    provider.origins.emplace(pubkey.GetID(), std::make_pair(pubkey, origin));

    const CScript multisig = GetScriptForMultisig(1, {pubkey});
    provider.scripts.emplace(CScriptID(multisig), multisig);

    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;
    PSBTInput input(2);
    input.prev_txid = uint256::ONE;
    input.prev_out = 0;
    psbt.inputs.push_back(input);

    PSBTOutput wpkh_out(2);
    wpkh_out.amount = 1'000;
    wpkh_out.script = GetScriptForDestination(WitnessV0KeyHash(pubkey));
    psbt.outputs.push_back(wpkh_out);

    PSBTOutput wsh_out(2);
    wsh_out.amount = 1'000;
    wsh_out.script = GetScriptForDestination(WitnessV0ScriptHash(multisig));
    psbt.outputs.push_back(wsh_out);

    PSBTOutput mweb_out(2);
    mweb_out.amount = 1'000;
    mweb_out.mweb_stealth_address = TestStealthAddress('1', '2');
    psbt.outputs.push_back(mweb_out);

    UpdatePSBTOutput(provider, psbt, 0);
    BOOST_CHECK_EQUAL(psbt.outputs[0].hd_keypaths.count(pubkey), 1U);

    UpdatePSBTOutput(provider, psbt, 1);
    BOOST_CHECK(psbt.outputs[1].witness_script == multisig);
    BOOST_CHECK_EQUAL(psbt.outputs[1].hd_keypaths.count(pubkey), 1U);

    // MWEB outputs are a no-op.
    UpdatePSBTOutput(provider, psbt, 2);
    BOOST_CHECK(psbt.outputs[2].witness_script.empty());
    BOOST_CHECK(psbt.outputs[2].hd_keypaths.empty());
}

BOOST_AUTO_TEST_CASE(psbt_input_get_utxo)
{
    CMutableTransaction prev;
    prev.vout.emplace_back(1'234, CScript() << OP_TRUE);
    const CTransactionRef prev_ref = MakeTransactionRef(prev);

    CTxOut utxo;

    // non_witness_utxo: hash and index must match.
    {
        PSBTInput input(2);
        input.non_witness_utxo = prev_ref;
        input.prev_txid = prev_ref->GetHash();
        input.prev_out = 0;
        BOOST_REQUIRE(input.GetUTXO(utxo));
        BOOST_CHECK_EQUAL(utxo.nValue, 1'234);

        input.prev_out = 5;
        BOOST_CHECK(!input.GetUTXO(utxo));

        input.prev_out = 0;
        input.prev_txid = uint256::ONE;
        BOOST_CHECK(!input.GetUTXO(utxo));
    }
    // witness_utxo fallback
    {
        PSBTInput input(2);
        input.prev_txid = uint256::ONE;
        input.prev_out = 0;
        input.witness_utxo = CTxOut(4'321, CScript() << OP_TRUE);
        BOOST_REQUIRE(input.GetUTXO(utxo));
        BOOST_CHECK_EQUAL(utxo.nValue, 4'321);
    }
    // neither
    {
        PSBTInput input(2);
        input.prev_txid = uint256::ONE;
        input.prev_out = 0;
        BOOST_CHECK(!input.GetUTXO(utxo));
    }
}

BOOST_AUTO_TEST_SUITE_END()
