#include <mw/crypto/Blinds.h>
#include <mw/models/crypto/Commitment.h>

#include <test_framework/TestMWEB.h>

BOOST_FIXTURE_TEST_SUITE(TestCommitment, MWEBTestingSetup)

BOOST_AUTO_TEST_CASE(CommitmentTest)
{
    // Inputs
    const BlindingFactor pre_blind = BlindingFactor::FromHex("7bf47c1624a38c31f4570381c66ab34006fd3cc8c07356db7cb9afdce88ea498");
    const uint64_t value = 8675309;

    // Verify calculation of blinding factor from pre-switch blind
    const BlindingFactor blind = Pedersen::BlindSwitch(pre_blind, value);
    BOOST_REQUIRE(blind.ToHex() == "48dc52d31ad9760bd8d2f45df961b8ee822d33940c52ef87dd95fb647145f6ff");

    // Verify calculation of commitment from pre-switch blind
    const Commitment commit_from_pre_blind = Commitment::Switch(pre_blind, value);
    BOOST_CHECK(commit_from_pre_blind.ToHex() == "08fdebb012641d300bd64023e4199ae39132ecac0ee2486818423e0d912686b253");

    // Verify calculation of commitment from blind
    const Commitment commit_from_blind = Commitment::Blinded(blind, value);
    BOOST_CHECK(commit_from_blind.ToHex() == "08fdebb012641d300bd64023e4199ae39132ecac0ee2486818423e0d912686b253");
}

BOOST_AUTO_TEST_SUITE_END()