#include <wallet/reserve.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

using namespace wallet;

util::Result<CTxDestination> ReserveDestination::GetReservedDestination(bool internal)
{
    // MWEB uses one address chain for both receive and change destinations.
    // Descriptor wallets therefore have no separate internal MWEB manager.
    const bool use_internal = internal && type != OutputType::MWEB;

    m_spk_man = pwallet->GetScriptPubKeyMan(type, use_internal);
    if (!m_spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    if (nIndex == -1) {
        m_spk_man->TopUp();

        CKeyPool keypool;
        auto op_address = m_spk_man->GetReservedDestination(type, use_internal, nIndex, keypool);
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
