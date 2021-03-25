#pragma once

#include <mw/common/BitSet.h>
#include <mw/common/Macros.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/MMRInfo.h>
#include <mw/mmr/PruneList.h>
#include <mw/models/crypto/Hash.h>
#include <libmw/libmw.h>

MMR_NAMESPACE

class MMRFactory
{
public:
    static MMR::Ptr Build(
        const char prefix,
        const std::shared_ptr<libmw::IDBWrapper>& pDBWrapper,
        const std::unique_ptr<libmw::IDBBatch>& pBatch,
        const PruneList::Ptr& pPruneList,
        const MMRInfo& mmr_info,
        const FilePath& data_dir,
        const BitSet& unspent_leaf_indices,
        const std::vector<Leaf>& unspent_leaves,
        const std::vector<mw::Hash>& pruned_parent_hashes
    );

    static std::vector<mw::Hash> CalcHashes(
        const BitSet& unspent_leaf_indices,
        const std::vector<Leaf>& unspent_leaves,
        const std::vector<mw::Hash>& pruned_parent_hashes
    );
};

END_NAMESPACE