Litecoin Core version 0.21.5.5 is now available from:

 <https://download.litecoin.org/litecoin-0.21.5.5/>.

This is a patch version release that includes important MWEB consensus
hardening, node reliability improvements, wallet and mining fixes, and
build/test updates.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

Notable changes
===============

Important MWEB updates
----------------------

This release contains important MWEB validation and state-handling fixes.
Upgrading is recommended for all users, especially miners, pools, and node
operators using MWEB.

- Added additional validation for MWEB inputs, pegins, HogEx data, kernel fees,
  and kernel lock heights (`e7cbf1d`, `42e7071`, `8f8ad64`, `b9bd99a`,
  `7564f05`, `a549004`).
- Hardened MWEB amount and fee calculations against overflow and invalid edge
  cases (`42e7071`, `1cd94bb`).
- Added fallback handling for rare hash-to-secret-key cases so derived MWEB
  keys are valid scalars (`773c138`).
- Added consensus parameters for known frozen or approved MWEB transactions and
  outputs needed to keep MWEB state balanced (`1dcbf3f`, `17f16ce`, `66f6856`).
- Improved handling of mutated or invalid MWEB block data so invalid data does
  not leave stale block data or mutate cached chainstate (`742ee94`, `ff309cd`,
  `17f16ce`).
- Updated MWEB chainstate during block replay and crash recovery (`bbd3b78`).

Network and policy changes
--------------------------

- Increased the maximum P2P protocol message length to 32 MB so valid MWEB
  blocks and messages fit under the message-size limit (`457bcd7`).
- Enforced standard script policy checks for pegout scripts (`c25bf89`).

Mining changes
--------------

- Avoid reading the previous block from disk when constructing HogEx
  transactions; use MWEB data already stored in the block index (`873d9d2`).
- Improved `getblocktemplate` fee and sigop accounting for transactions carrying
  MWEB data (`873d9d2`).
- Avoid including MWEB transactions in candidate blocks when their input and
  output commitments would sum to zero (`f423a84`).

Wallet and RPC changes
----------------------

- Fixed MWEB balance and pegout accounting (`1dcbf3f`, `1cc1cee`).
- Added MWEB view keys to `dumpwallet` (`eae9e47`).
- Supported `maxfeerate=0` for MWEB transactions in `sendrawtransaction` and
  `testmempoolaccept` (`8782ab9`).
- Allowed `getblocktemplate` on test chains when the node is unconnected or in
  initial block download (`455aff8`).

Bug fixes
---------

- Fixed MWEB PMMR rewind corruption and improved MMR file write durability
  (`23e5eac`, `bf25a7c`, `3110a7e`).
- Fixed a cache leaf bounds check (`6dd2952`).
- Fixed a transaction index consistency issue that could occur if writing block
  data failed after the index commit (`eb7f68a`).
- Fixed wallet loading with Boost 1.78 and newer (`3c3aedb`, `c882663`).
- Fixed a debug build logger symbol conflict and made MWEB logger initialization
  safer (`6fc0530`, `b4c0037`).

Build and test changes
----------------------

- Added missing `<cstdint>` includes needed by some compilers (`58f89ba`).
- Replaced the functional test dependency on the external `litecoin_scrypt`
  Python package (`d139222`).
- Added and expanded tests for MWEB P2P messages, duplicate pegins, crash
  recovery, mutated blocks, mining, and wallet/RPC behavior.
- Normalized line endings in selected documentation, Qt resources, and fuzz test
  files (`dcc7bc5`).
- Fixed the broken Transifex link in the README (`0f5f7d5`).

Credits
=======

Thanks to everyone who directly contributed to this release:

- [David Burkett](https://github.com/DavidBurkett/)
- [Loshan](https://github.com/losh11)
