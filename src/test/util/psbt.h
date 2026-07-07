// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_PSBT_H
#define BITCOIN_TEST_UTIL_PSBT_H

#include <key.h>
#include <mw/models/tx/Input.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/tx/Output.h>
#include <psbt.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

//! Deterministic builders and (de)serialization helpers for PSBT unit tests.
//! Everything here is pure and deterministic: the same call always produces
//! the same bytes, so serialized forms can be pinned as golden vectors.
namespace psbt_test {

//! Deterministic secret from a repeated hex character ('0'..'9', 'a'..'f').
inline SecretKey TestSecret(char hex_char)
{
    return SecretKey::FromHex(std::string(64, hex_char));
}

inline PublicKey TestPubKey(char hex_char)
{
    return PublicKey::From(TestSecret(hex_char));
}

//! Asserts the secret is a valid ECDSA key: repeated-'f' secrets (0xff...f)
//! exceed the secp256k1 group order and fail deep inside CKey otherwise.
inline CKey ToCKey(const SecretKey& secret)
{
    CKey key;
    key.Set(secret.vec().begin(), secret.vec().end(), /*fCompressedIn=*/true);
    assert(key.IsValid());
    return key;
}

inline Commitment TestCommitment(uint64_t value)
{
    return Commitment::Transparent(value);
}

//! Not a valid Schnorr signature; only for serialization tests.
inline Signature TestSignature(char hex_char)
{
    return Signature::FromHex(std::string(128, hex_char));
}

//! Not a valid bulletproof; only for serialization tests.
inline RangeProof::CPtr TestRangeProof(uint8_t seed)
{
    std::vector<uint8_t> bytes(RangeProof::SIZE);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(seed + i);
    }
    return std::make_shared<RangeProof>(std::move(bytes));
}

inline StealthAddress TestStealthAddress(char scan_hex_char, char spend_hex_char)
{
    return StealthAddress(TestPubKey(scan_hex_char), TestPubKey(spend_hex_char));
}

inline mw::Hash TestHash(uint8_t value)
{
    return mw::Hash::ValueOf(value);
}

//! Build a PSBTProprietary whose raw key bytes are consistent with its parsed
//! identifier/subtype, so it round-trips through (de)serialization.
inline PSBTProprietary TestProprietary(const std::string& identifier = "test", uint64_t subtype = 42)
{
    PSBTProprietary prop;
    prop.identifier.assign(identifier.begin(), identifier.end());
    prop.subtype = subtype;
    prop.value = {0x0f, 0x0e};

    CDataStream key_stream(SER_NETWORK, PROTOCOL_VERSION);
    key_stream << CompactSizeWriter(PSBT_IN_PROPRIETARY); // 0xFC for every map type
    key_stream << prop.identifier;
    key_stream << CompactSizeWriter(subtype);
    const Span<const unsigned char> key_bytes = MakeUCharSpan(key_stream);
    prop.key.assign(key_bytes.begin(), key_bytes.end());
    return prop;
}

//! Minimal MWEB input: just the output ID.
inline PSBTInput MWEBInput(const mw::Hash& output_id, uint32_t version = 2)
{
    PSBTInput input(version);
    input.mweb_output_id = output_id;
    return input;
}

//! An MWEB input with every MWEB keytype populated deterministically
//! (0x90-0x99, 0x9C), plus one unknown and one proprietary key.
//! Not cryptographically valid; freezes the wire format only.
inline PSBTInput FullMWEBInput(uint32_t version = 2)
{
    PSBTInput input(version);
    input.mweb_output_id = TestHash(0x11);
    input.mweb_output_commit = TestCommitment(1);
    input.mweb_output_pubkey = TestPubKey('2');
    input.mweb_input_pubkey = TestPubKey('3');
    input.mweb_features = mw::Input::STEALTH_KEY_FEATURE_BIT | mw::Input::EXTRA_DATA_FEATURE_BIT;
    input.mweb_sig = TestSignature('4');
    input.mweb_amount = 12345;
    input.mweb_shared_secret = TestSecret('5');
    input.mweb_key_exchange_pubkey = TestPubKey('6');
    input.mweb_extra_data = {0xde, 0xad, 0xbe, 0xef};
    input.mweb_address_descriptor = "mweb(test)";
    input.unknown[{0xa0}] = {0x01, 0x02};
    input.m_proprietary.insert(TestProprietary());
    return input;
}

//! An MWEB output with every MWEB keytype populated deterministically
//! (0x90-0x98), plus one unknown and one proprietary key.
inline PSBTOutput FullMWEBOutput(uint32_t version = 2)
{
    PSBTOutput output(version);
    output.amount = 90'000;
    output.mweb_stealth_address = TestStealthAddress('7', '8');
    output.mweb_commit = TestCommitment(2);
    output.mweb_features = mw::OutputMessage::STANDARD_FIELDS_FEATURE_BIT | mw::OutputMessage::EXTRA_DATA_FEATURE_BIT;
    output.mweb_sender_pubkey = TestPubKey('9');
    output.mweb_output_pubkey = TestPubKey('a');
    output.mweb_extra_data = {0xca, 0xfe};
    output.mweb_standard_fields = mw::OutputStandardFields(
        TestPubKey('b'), /*viewTag=*/0x42, /*maskedValue=*/987654321,
        BigInt<16>::FromHex(std::string(32, 'c')));
    output.mweb_rangeproof = TestRangeProof(3);
    output.mweb_sig = TestSignature('d');
    output.unknown[{0xa0}] = {0x03, 0x04};
    output.m_proprietary.insert(TestProprietary());
    return output;
}

//! A kernel with every keytype populated (0x00-0x08) including two pegouts
//! (exercises the indexed PSBT_KERN_PEGOUT key encoding), plus one unknown
//! key. The features byte is consistent with the populated fields.
inline PSBTKernel FullKernel()
{
    PSBTKernel kernel;
    kernel.commit = TestCommitment(4);
    kernel.stealth_commit = TestPubKey('e');
    kernel.fee = 1'000;
    kernel.pegin_amount = 5'000;
    kernel.pegouts.emplace_back(600, CScript() << OP_0 << std::vector<unsigned char>(20, 0x01));
    kernel.pegouts.emplace_back(700, CScript() << OP_0 << std::vector<unsigned char>(20, 0x02));
    kernel.lock_height = 123;
    kernel.extra_data = {0x99};
    kernel.sig = TestSignature('f');
    kernel.features = mw::Kernel::FEE_FEATURE_BIT | mw::Kernel::PEGIN_FEATURE_BIT |
                      mw::Kernel::PEGOUT_FEATURE_BIT | mw::Kernel::HEIGHT_LOCK_FEATURE_BIT |
                      mw::Kernel::STEALTH_EXCESS_FEATURE_BIT | mw::Kernel::EXTRA_DATA_FEATURE_BIT;
    kernel.unknown[{0xa0}] = {0x05, 0x06};
    return kernel;
}

//! A PSBTv2 exercising every map type: one canonical + one MWEB input, one
//! canonical + one MWEB output, one all-fields kernel, both global offsets,
//! fallback locktime, tx modifiable flags, and unknown/proprietary keys in
//! the global map. Its serialization is pinned as PSBT_V2_ALLFIELDS.
inline PartiallySignedTransaction AllFieldsPSBT()
{
    PartiallySignedTransaction psbt;
    psbt.m_psbt_version = 2;
    psbt.tx_version = 2;
    psbt.fallback_locktime = 1'000;
    psbt.m_tx_modifiable = std::bitset<8>{0x03};
    psbt.mweb_tx_offset = TestSecret('1');
    psbt.mweb_stealth_offset = TestSecret('2');
    psbt.unknown[{0xa0}] = {0x07, 0x08};
    psbt.m_proprietary.insert(TestProprietary());

    PSBTInput canonical_input(2);
    canonical_input.prev_txid = uint256::ONE;
    canonical_input.prev_out = 0;
    canonical_input.sequence = 0xfffffffe;
    psbt.inputs.push_back(canonical_input);
    psbt.inputs.push_back(FullMWEBInput()); // MWEB inputs must be last

    PSBTOutput canonical_output(2);
    canonical_output.amount = 50'000;
    canonical_output.script = CScript() << OP_0 << std::vector<unsigned char>(20, 0x03);
    psbt.outputs.push_back(canonical_output);
    psbt.outputs.push_back(FullMWEBOutput()); // MWEB outputs must be last

    psbt.kernels.push_back(FullKernel());
    return psbt;
}

inline std::vector<unsigned char> Ser(const PartiallySignedTransaction& psbt)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << psbt;
    const Span<const unsigned char> bytes = MakeUCharSpan(ss);
    return std::vector<unsigned char>(bytes.begin(), bytes.end());
}

inline std::string SerHex(const PartiallySignedTransaction& psbt)
{
    return HexStr(Ser(psbt));
}

//! Decode raw PSBT bytes, requiring success.
inline PartiallySignedTransaction Deser(Span<const unsigned char> bytes)
{
    PartiallySignedTransaction psbt;
    std::string error;
    BOOST_REQUIRE_MESSAGE(DecodeRawPSBT(psbt, MakeByteSpan(bytes), error), error);
    return psbt;
}

//! Decode a hex-encoded PSBT (the golden-vector format), requiring success.
inline PartiallySignedTransaction DecodeHexPSBT(const std::string& hex)
{
    BOOST_REQUIRE(IsHex(hex));
    return Deser(ParseHex(hex));
}

//! serialize -> deserialize -> serialize must be byte-identical.
inline void CheckRoundTrip(const PartiallySignedTransaction& psbt)
{
    const std::vector<unsigned char> bytes = Ser(psbt);
    const PartiallySignedTransaction decoded = Deser(bytes);
    BOOST_CHECK_EQUAL(HexStr(bytes), HexStr(Ser(decoded)));
}

//! Remove all MWEB signatures, proofs, commitments, and offsets, returning
//! the PSBT to a not-yet-signed state (canonical fields are left untouched).
inline PartiallySignedTransaction StripMWEBSignatures(PartiallySignedTransaction psbt)
{
    for (PSBTInput& input : psbt.inputs) {
        input.mweb_sig.reset();
    }
    for (PSBTOutput& output : psbt.outputs) {
        output.mweb_sig.reset();
        output.mweb_rangeproof.reset();
        output.mweb_commit.reset();
    }
    for (PSBTKernel& kernel : psbt.kernels) {
        kernel.sig.reset();
        kernel.commit.reset();
        kernel.stealth_commit.reset();
        kernel.features.reset();
    }
    psbt.mweb_tx_offset.reset();
    psbt.mweb_stealth_offset.reset();
    return psbt;
}

} // namespace psbt_test

#endif // BITCOIN_TEST_UTIL_PSBT_H
