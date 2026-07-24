#pragma once

#include <string>

// Forward Declarations
class CTransaction;

namespace MWEB {

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

    /// <summary>
    /// Cheaply checks that an MWEB transaction is within the relay weight/input
    /// limits (much tighter than the consensus limits). Intended to run before
    /// the expensive signature/rangeproof verification in
    /// MWEB::Node::CheckTransaction, to prevent a cheap-to-relay,
    /// expensive-to-verify DoS.
    /// </summary>
    /// <param name="tx">The transaction to check.</param>
    /// <param name="reason">The reason it's non-standard, if any.</param>
    /// <returns>True if the transaction is within the relay limits.</returns>
    static bool CheckWeight(const CTransaction& tx, std::string& reason);
};

}