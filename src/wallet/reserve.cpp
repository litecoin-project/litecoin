#include <wallet/reserve.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

using namespace wallet;

util::Result<CTxDestination> ReserveDestination::GetReservedDestination(bool internal)
{
    m_spk_man = pwallet->GetScriptPubKeyMan(type, internal);
    if (!m_spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    if (nIndex == -1) {
        m_spk_man->TopUp();

        CKeyPool keypool;
        auto op_address = m_spk_man->GetReservedDestination(type, internal, nIndex, keypool);
        if (!op_address) return op_address;
        address = *op_address;
        fInternal = keypool.fInternal;
    }

    return address;
}

void ReserveDestination::KeepDestination()
{
    if (nIndex != -1) {
        m_spk_man->KeepDestination(nIndex, type);
    }
    nIndex = -1;
    address = CNoDestination();
}

void ReserveDestination::ReturnDestination()
{
    if (nIndex != -1) {
        KeyPurpose purpose = GetPurpose(type, fInternal);
        m_spk_man->ReturnDestination(nIndex, purpose, address);
    }
    nIndex = -1;
    address = CNoDestination();
}
