#pragma once

#include <libmw/interfaces/db_interface.h>
#include <mw/exceptions/NotFoundException.h>
#include <map>

class TestDBBatch : public libmw::IDBBatch
{
    struct Action
    {
        bool is_delete;
        std::string key;
        std::vector<uint8_t> value;
    };

public:
    TestDBBatch(std::map<std::string, std::vector<uint8_t>>& kvp)
        : m_kvp(kvp)
    {

    }

    void Write(const std::string& key, const std::vector<uint8_t>& value) final
    {
        m_actions.push_back({ false, key, value });
    }

    void Erase(const std::string& key) final
    {
        m_actions.push_back({ true, key, std::vector<uint8_t>{} });
    }

    void Commit() final
    {
        for (const Action& action : m_actions) {
            if (action.is_delete) {
                auto iter = m_kvp.find(action.key);
                if (iter != m_kvp.end()) {
                    m_kvp.erase(iter);
                } else {
                    ThrowNotFound_F("Key {} not found", action.key);
                }
            } else {
                m_kvp[action.key] = action.value;
            }
        }

        m_actions.clear();
    }

private:
    std::map<std::string, std::vector<uint8_t>>& m_kvp;
    std::vector<Action> m_actions;
};

class TestDBIterator : public libmw::IDBIterator
{
public:
    TestDBIterator(const std::map<std::string, std::vector<uint8_t>>& kvp)
        : m_kvp(kvp), m_iter(m_kvp.cbegin())
    {

    }

    void Seek(const std::string& key) final
    {
        for (m_iter = m_kvp.cbegin(); m_iter != m_kvp.cend(); m_iter++) {
            if (key.compare(m_iter->first) <= 0) {
                break;
            }
        }
    }

    void Next() final
    {
        m_iter++;
    }

    bool GetKey(std::string& key) const final
    {
        if (Valid()) {
            key = m_iter->first;
            return true;
        }

        return false;
    }

    bool Valid() const final
    {
        return m_iter != m_kvp.cend();
    }

private:
    std::map<std::string, std::vector<uint8_t>> m_kvp;
    std::map<std::string, std::vector<uint8_t>>::const_iterator m_iter;
};

class TestDBWrapper : public libmw::IDBWrapper
{
public:
    TestDBWrapper() = default;

    bool Read(const std::string& key, std::vector<uint8_t>& value) const final
    {
        auto iter = m_kvp.find(key);
        if (iter != m_kvp.end()) {
            value = iter->second;
            return true;
        }

        return false;
    }

    void Write(const std::string& key, const std::vector<uint8_t>& value)
    {
        m_kvp[key] = value;
    }

    void Delete(const std::string& key)
    {
        auto iter = m_kvp.find(key);
        if (iter != m_kvp.end()) {
            m_kvp.erase(iter);
            return;
        }

        ThrowNotFound_F("Key {} not found", key);
    }

    std::unique_ptr<libmw::IDBIterator> NewIterator() final
    {
        return std::unique_ptr<libmw::IDBIterator>(new TestDBIterator(m_kvp));
    }

    std::unique_ptr<libmw::IDBBatch> CreateBatch() final
    {
        return std::unique_ptr<libmw::IDBBatch>(new TestDBBatch(m_kvp));
    }

private:
    std::map<std::string, std::vector<uint8_t>> m_kvp;
};