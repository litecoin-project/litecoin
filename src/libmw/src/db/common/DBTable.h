#pragma once

#include "DBEntry.h"

#include <memory>
#include <string>

class DBTable
{
public:
    struct Options
    {
        static Options Default() { return Options({ false }); }

        // Can there be multiple entries per key?
        bool allowDuplicates;
    };

    DBTable(const char prefix, const Options& options = Options::Default())
        : m_prefix(prefix), m_options(options) { }

    std::string BuildKey(const std::string& itemKey) const noexcept { return m_prefix + itemKey; }

    template<typename T,
        typename SFINAE = typename std::enable_if_t<std::is_base_of_v<Traits::ISerializable, T>>>
    std::string BuildKey(const DBEntry<T>& item) const noexcept { return BuildKey(item.key); }

    char GetPrefix() const noexcept { return m_prefix; }

private:
    char m_prefix;
    Options m_options;
};