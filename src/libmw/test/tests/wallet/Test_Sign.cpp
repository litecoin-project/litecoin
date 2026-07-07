#include <consensus/validation.h>
#include <mweb/mweb_node.h>
#include <mw/models/tx/Kernel.h>
#include <mw/models/wallet/StealthAddress.h>
#include <mw/wallet/sign.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <test_framework/TestMWEB.h>

#include <set>

BOOST_FIXTURE_TEST_SUITE(TestSign, MWEBTestingSetup)

namespace
{
static void CheckPegInScriptsMatchKernelIDs(const CMutableTransaction& tx)
{
    std::set<mw::Hash> output_kernel_ids;
    for (const CTxOut& out : tx.vout) {
        mw::Hash kernel_id;
        BOOST_REQUIRE(out.scriptPubKey.IsMWEBPegin(&kernel_id));
        output_kernel_ids.insert(kernel_id);
    }

    BOOST_REQUIRE_EQUAL(output_kernel_ids.size(), tx.mweb_tx.kernels.size());

    for (const mw::MutableKernel& kernel : tx.mweb_tx.kernels) {
        const std::optional<mw::Hash> kernel_id = kernel.GetKernelID();
        BOOST_REQUIRE(kernel_id.has_value());
        BOOST_CHECK(output_kernel_ids.count(*kernel_id) == 1);
    }

    TxValidationState state;
    BOOST_CHECK(MWEB::Node::CheckTransaction(CTransaction(tx), state));
}
} // namespace

BOOST_AUTO_TEST_CASE(MultiplePegInsSameAmount)
{
    static constexpr CAmount PEG_IN_AMOUNT{10'000'000};

    CMutableTransaction tx;
    tx.vout = {
        CTxOut{PEG_IN_AMOUNT, GetScriptForPegin(mw::Hash{})},
        CTxOut{PEG_IN_AMOUNT, GetScriptForPegin(mw::Hash{})}
    };

    for (size_t i = 0; i < 2; ++i) {
        mw::MutableOutput output;
        output.amount = PEG_IN_AMOUNT;
        output.address = StealthAddress::Random();
        tx.mweb_tx.outputs.push_back(std::move(output));

        mw::MutableKernel kernel;
        kernel.pegin = PEG_IN_AMOUNT;
        tx.mweb_tx.kernels.push_back(std::move(kernel));
    }

    const auto sign_result = mw::SignTx(tx, SecretKey::Random(), []() -> util::Result<SecretKey> {
        return SecretKey::Random();
    });
    BOOST_REQUIRE(sign_result);

    CheckPegInScriptsMatchKernelIDs(tx);
}

BOOST_AUTO_TEST_SUITE_END()
