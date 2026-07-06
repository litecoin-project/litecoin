// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/hasher.h>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <memory>
#include <numeric>
#include <unordered_set>

bool CheckPackage(const Package& txns, PackageValidationState& state)
{
    const unsigned int package_count = txns.size();

    if (package_count > MAX_PACKAGE_COUNT) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-many-transactions");
    }

    const int64_t total_size = std::accumulate(txns.cbegin(), txns.cend(), 0,
                               [](int64_t sum, const auto& tx) { return sum + GetVirtualTransactionSize(*tx); });
    // If the package only contains 1 tx, it's better to report the policy violation on individual tx size.
    if (package_count > 1 && total_size > MAX_PACKAGE_SIZE * 1000) {
        return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
    }

    // Require the package to be sorted in order of dependency, i.e. parents appear before children.
    // An unsorted package will fail anyway on missing-inputs, but it's better to quit earlier and
    // fail on something less ambiguous (missing-inputs could also be an orphan or trying to
    // spend nonexistent coins).
    std::unordered_set<AnyOutputID, SaltedOutputIDHasher> later_output_ids;
    for (const auto& tx : txns) {
        for (const AnyOutput& output : tx->GetOutputs()) {
            later_output_ids.insert(output.GetID());
        }
    }
    for (const auto& tx : txns) {
        for (const AnyInput& input : tx->GetInputs()) {
            if (later_output_ids.find(input.GetID()) != later_output_ids.end()) {
                // The parent is a subsequent transaction in the package.
                return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-sorted");
            }
        }
        for (const AnyOutput& output : tx->GetOutputs()) {
            later_output_ids.erase(output.GetID());
        }
    }

    // Don't allow any conflicting transactions, i.e. spending the same inputs, in a package.
    std::unordered_set<AnyOutputID, SaltedOutputIDHasher> inputs_seen;
    for (const auto& tx : txns) {
        std::vector<AnyInput> inputs = tx->GetInputs();
        for (const AnyInput& input : inputs) {
            if (inputs_seen.find(input.GetID()) != inputs_seen.end()) {
                // This input is also present in another tx in the package.
                return state.Invalid(PackageValidationResult::PCKG_POLICY, "conflict-in-package");
            }
        }
        // Batch-add all the inputs for a tx at a time. If we added them 1 at a time, we could
        // catch duplicate inputs within a single tx.  This is a more severe, consensus error,
        // and we want to report that from CheckTransaction instead.
        for (const AnyInput& input : inputs) {
            inputs_seen.insert(input.GetID());
        }
    }
    return true;
}

bool IsChildWithParents(const Package& package)
{
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));
    if (package.size() < 2) return false;

    // The package is expected to be sorted, so the last transaction is the child.
    const auto& child = package.back();
    std::unordered_set<AnyOutputID, SaltedOutputIDHasher> input_ids;
    for (const AnyInput& input : child->GetInputs()) {
        input_ids.insert(input.GetID());
    }

    // Every transaction must be a parent of the last transaction in the package.
    return std::all_of(package.cbegin(), package.cend() - 1,
                       [&input_ids](const auto& ptx) {
                           const std::vector<AnyOutput> outputs = ptx->GetOutputs();
                           return std::any_of(outputs.cbegin(), outputs.cend(), [&input_ids](const AnyOutput& output) {
                               return input_ids.count(output.GetID()) > 0;
                           });
                       });
}
