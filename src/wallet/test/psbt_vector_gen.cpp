// Copyright (c) 2026 The Litecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Generator harness for the golden PSBT vectors in test/util/psbt_vectors.h.
//
// Every gen_* case is disabled: MWEB signing draws random blinds and
// ephemeral keys, so each run produces different (equally valid) bytes.
// The cases stay compiled so they cannot bit-rot. To (re)generate a vector:
//
//   src/test/test_litecoin --run_test=psbt_vector_gen/<case> --log_level=message
//
// then paste the printed hex into test/util/psbt_vectors.h. See the
// regeneration policy at the top of that header before doing so.

#include <key.h>
#include <psbt.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <test/util/psbt.h>
#include <test/util/psbt_vectors.h>
#include <test/util/setup_common.h>
#include <wallet/mweb_psbt.h>
#include <wallet/test/psbt_test_utils.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

using test::MWEBTestKeys;
using test::PeginTx;
using test::SignableMWEBPSBT;
using test::TestSecret;
using test::TestSenderKeyGenerator;

BOOST_FIXTURE_TEST_SUITE(psbt_vector_gen, BasicTestingSetup)

namespace {

void PrintVector(const std::string& name, const PartiallySignedTransaction& psbt)
{
    BOOST_TEST_MESSAGE("VECTOR " << name << " = " << psbt_test::SerHex(psbt));
}

//! Common validity gate every crypto-bearing vector must pass before being pinned.
void AssertFullyValid(const PartiallySignedTransaction& psbt)
{
    BOOST_REQUIRE(psbt.IsComplete());
    for (unsigned int i = 0; i < psbt.inputs.size(); ++i) {
        BOOST_REQUIRE(PSBTInputSignedAndVerified(psbt, i, nullptr));
    }

    PartiallySignedTransaction to_finalize = psbt;
    const util::Result<CMutableTransaction> final_tx = FinalizePSBT(to_finalize);
    BOOST_REQUIRE(bool{final_tx});
    const CTransaction tx{*final_tx};
    BOOST_REQUIRE(!tx.mweb_tx.IsNull());
    BOOST_REQUIRE(!tx.mweb_tx.m_transaction->Validate());
}

//! The signed MWEB-to-MWEB structure used for PSBT_MWEB_SIGNED and its _ALT twin.
PartiallySignedTransaction SignedMWEBToMWEB()
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = mw::Hash::ValueOf(1);

    PartiallySignedTransaction psbt = SignableMWEBPSBT(output_id, TestSecret('b'), keys.Address(0));
    const std::unordered_map<mw::Hash, SecretKey> spend_keys{{output_id, TestSecret('a')}};
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, spend_keys, TestSecret('c'), TestSenderKeyGenerator())});
    AssertFullyValid(psbt);
    return psbt;
}

} // namespace

//! ENABLED: the all-fields vector is byte-reproducible from its builder, so
//! any divergence between the builder and the pinned bytes is a real failure.
BOOST_AUTO_TEST_CASE(gen_allfields_check)
{
    const std::string hex = psbt_test::SerHex(psbt_test::AllFieldsPSBT());
    if (hex != psbt_test::PSBT_V2_ALLFIELDS) {
        BOOST_TEST_MESSAGE("VECTOR PSBT_V2_ALLFIELDS = " << hex);
    }
    BOOST_CHECK_EQUAL(hex, psbt_test::PSBT_V2_ALLFIELDS);
}

BOOST_AUTO_TEST_CASE(gen_mweb_signed, *boost::unit_test::disabled())
{
    PrintVector("PSBT_MWEB_SIGNED", SignedMWEBToMWEB());
}

BOOST_AUTO_TEST_CASE(gen_mweb_signed_alt, *boost::unit_test::disabled())
{
    // An independent signing of the same pre-sign structure: structurally
    // merge-compatible with PSBT_MWEB_SIGNED but cryptographically conflicting.
    PrintVector("PSBT_MWEB_SIGNED_ALT", SignedMWEBToMWEB());
}

BOOST_AUTO_TEST_CASE(gen_pegin_signed, *boost::unit_test::disabled())
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();

    PartiallySignedTransaction psbt(PeginTx(keys.Address(0)), 2);
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator())});
    AssertFullyValid(psbt);

    // The placeholder peg-in script must have been rewritten to commit to the
    // finalized kernel's ID.
    mw::Hash script_kernel_id;
    BOOST_REQUIRE(psbt.outputs[0].script.has_value());
    BOOST_REQUIRE(psbt.outputs[0].script->IsMWEBPegin(&script_kernel_id));
    const CMutableTransaction mtx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(mtx.mweb_tx.kernels[0].GetKernelID().has_value());
    BOOST_REQUIRE(script_kernel_id == *mtx.mweb_tx.kernels[0].GetKernelID());

    PrintVector("PSBT_PEGIN_SIGNED", psbt);
}

BOOST_AUTO_TEST_CASE(gen_mixed_signed, *boost::unit_test::disabled())
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const CKey key = MWEBTestKeys::ToCKey(TestSecret('7'));
    const CScript wpkh_script = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    CMutableTransaction mtx = PeginTx(keys.Address(0));
    mtx.vin.emplace_back(COutPoint(uint256::ONE, 0));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs[0].witness_utxo = CTxOut(110'000, wpkh_script);

    // MWEB signing first: it rewrites the peg-in script, which the canonical
    // signature must commit to.
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, /*spend_keys=*/{}, TestSecret('c'), TestSenderKeyGenerator())});

    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);
    BOOST_REQUIRE(SignPSBTInput(provider, psbt, 0, &txdata, SIGHASH_ALL, nullptr, /*finalize=*/true));

    AssertFullyValid(psbt);
    PrintVector("PSBT_MIXED_SIGNED", psbt);
}

BOOST_AUTO_TEST_CASE(gen_pegout_signed, *boost::unit_test::disabled())
{
    const MWEBTestKeys keys = MWEBTestKeys::Create();
    const mw::Hash output_id = mw::Hash::ValueOf(2);
    const CKey pegout_key = MWEBTestKeys::ToCKey(TestSecret('e'));
    const CScript pegout_script = GetScriptForDestination(WitnessV0KeyHash(pegout_key.GetPubKey()));

    CMutableTransaction mtx;
    mw::MutableInput input(output_id);
    input.amount = 100'000;
    mtx.mweb_tx.inputs.push_back(std::move(input));

    mw::MutableOutput output;
    output.amount = 40'000;
    output.address = keys.Address(0);
    mtx.mweb_tx.outputs.push_back(std::move(output));

    mw::MutableKernel kernel;
    kernel.fee = 10'000;
    kernel.SetPegOuts({PegOutCoin(50'000, pegout_script)});
    mtx.mweb_tx.kernels.push_back(std::move(kernel));

    PartiallySignedTransaction psbt(mtx, 2);
    psbt.inputs[0].mweb_shared_secret = TestSecret('b');

    const std::unordered_map<mw::Hash, SecretKey> spend_keys{{output_id, TestSecret('a')}};
    BOOST_REQUIRE(bool{SignPSBTMWEBComponents(psbt, spend_keys, TestSecret('c'), TestSenderKeyGenerator())});
    AssertFullyValid(psbt);
    PrintVector("PSBT_PEGOUT_SIGNED", psbt);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
