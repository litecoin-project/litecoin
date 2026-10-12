#pragma once

#include <string>

// Forward Declarations
class CTransaction;

namespace MWEB {

/** Peg-out data carriers retain the 83-byte script limit, including OP_RETURN and push opcodes. */
static constexpr unsigned int MAX_PEGOUT_OP_RETURN_RELAY{83};

class Policy
{
public:
    /// <summary>
    /// Checks the transaction for violation of any MWEB-specific standard tx policies.
    /// </summary>
    /// <param name="tx">The transaction to check.</param>
    /// <param name="reason">The reason it's non-standard, if any.</param>
    /// <returns>True if the transaction is standard.</returns>
    static bool IsStandardTx(const CTransaction& tx, std::string& reason);

    /// Cheaply checks MWEB relay weight and input limits before expensive
    /// signature and rangeproof verification.
    static bool CheckWeight(const CTransaction& tx, std::string& reason);
};

}
