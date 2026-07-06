#include <script/address.h>
#include <key_io.h>

GenericAddress::GenericAddress(const CTxDestination& dest)
{
    if (std::holds_alternative<StealthAddress>(dest)) {
        m_script = std::get<StealthAddress>(dest);
    } else {
        m_script = ::GetScriptForDestination(dest);
    }
}

std::string GenericAddress::Encode() const
{
    CTxDestination dest;
    if (ExtractDestination(dest)) {
        return ::EncodeDestination(dest);
    }

    return HexStr(GetScript());
}

const CScript& GenericAddress::GetScript() const noexcept
{
    assert(std::holds_alternative<CScript>(m_script));
    return std::get<CScript>(m_script);
}

const StealthAddress& GenericAddress::GetMWEBAddress() const noexcept
{
    assert(std::holds_alternative<StealthAddress>(m_script));
    return std::get<StealthAddress>(m_script);
}

bool GenericAddress::ExtractDestination(CTxDestination& dest) const
{
    if (IsMWEB()) {
        dest = GetMWEBAddress();
        return true;
    }
    return ::ExtractDestination(GetScript(), dest);
}
