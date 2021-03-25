#pragma once

#include <mw/common/Macros.h>
#include <mw/mmr/MMR.h>
#include <mw/mmr/backends/VectorBackend.h>
#include <type_traits>

TEST_NAMESPACE

class RootCalculator
{
public:
    template<class T, typename = std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    static mw::Hash CalculateRoot(const std::vector<T>& leaves)
    {
		assert(!leaves.empty());

		auto mmr = mmr::MMR(std::make_shared<mmr::VectorBackend>());
        for (size_t leafIdx = 0; leafIdx < leaves.size(); leafIdx++)
        {
			mmr.Add(leaves[leafIdx].Serialized());
		}

		return mmr.Root();
    }
};

END_NAMESPACE