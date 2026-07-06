#pragma once

#include <script/standard.h>
#include <variant>

//
// A wrapper around a boost::variant<CScript, StealthAddress> to deal with cases where
// a raw CScript is passed around as an address, rather than a CTxDestination.
// Since StealthAddresses can't be represented as a CScript, this wrapper should be used
// wherever the address could contain a StealthAddress instead of a CScript
//
class GenericAddress
{
public:
    GenericAddress() = default;
    GenericAddress(CScript script)
        : m_script(std::move(script)) {}
    GenericAddress(StealthAddress address)
        : m_script(std::move(address)) {}
    GenericAddress(const CTxDestination& dest);

    bool operator==(const GenericAddress& rhs) const noexcept { return this->m_script == rhs.m_script; }
    bool operator<(const GenericAddress& rhs) const noexcept { return this->m_script < rhs.m_script; }
    bool operator<=(const GenericAddress& rhs) const noexcept { return this->m_script <= rhs.m_script; }

    std::string Encode() const;

    bool IsMWEB() const noexcept { return std::holds_alternative<StealthAddress>(m_script); }
    bool IsEmpty() const noexcept { return !IsMWEB() && GetScript().empty(); }

    const CScript& GetScript() const noexcept;
    const StealthAddress& GetMWEBAddress() const noexcept;
    bool ExtractDestination(CTxDestination& dest) const;

private:
    std::variant<CScript, StealthAddress> m_script;
};

class SaltedGenericAddressHasher
{
private:
    /** Salt */
    const uint64_t m_k0, m_k1;

public:
    SaltedGenericAddressHasher() : m_k0(GetRand<uint64_t>()), m_k1(GetRand<uint64_t>()) {}

    size_t operator()(const GenericAddress& dest_addr) const noexcept
    {
        std::string encoded = dest_addr.Encode();
        return CSipHasher(m_k0, m_k1).Write((const unsigned char*)encoded.data(), encoded.size()).Finalize();
    }
};
