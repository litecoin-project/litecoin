#pragma once

#include <libmw/defs.h>
#include <mw/models/tx/Output.h>
#include <mw/wallet/Keychain.h>

class Wallet
{
public:
    Wallet(const mw::Keychain::Ptr& pKeychain)
        : m_pKeychain(pKeychain) { }

    bool RewindOutput(const Output& output, libmw::Coin& coin) const;

private:
    mw::Keychain::Ptr m_pKeychain;
};