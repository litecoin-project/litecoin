# MWEB Wallet

## Legacy Wallets (bdb)

* Legacy watch-only wallets do *NOT* support MWEB.
* Legacy wallets do *NOT* support importing MWEB addresses.
* Legacy wallets do *NOT* support changing seed once MWEB support has been enabled.
* Chains with MWEB enabled cannot be marked inactive. Only the currently active chain could have MWEB support.

### Key Derivation

The legacy MWEB wallet uses the following HD keychain paths:

 * `m/0'/100'/0'`- Master Scan Key
 * `m/0'/100'/1'`- Master Spend Key

## Descriptor Wallets (sqlite)

