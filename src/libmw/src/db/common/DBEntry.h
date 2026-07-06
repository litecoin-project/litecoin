#pragma once

#include <string>
#include <memory>
#include <utility>

template<typename T>
struct DBEntry
{
    DBEntry(const std::string& _key, const std::shared_ptr<const T>& _item)
        : key(_key), item(_item) { }

    DBEntry(const std::string& _key, T _item)
        : key(_key), item(std::make_shared<const T>(std::move(_item))) { }

    std::string key;
    std::shared_ptr<const T> item;
};
