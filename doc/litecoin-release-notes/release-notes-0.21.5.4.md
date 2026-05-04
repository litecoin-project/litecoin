0.21.5.4 Release Notes
====================

Litecoin Core version 0.21.5.4 is now available from:

 <https://download.litecoin.org/litecoin-0.21.5.4/>.

This release includes important security updates. All node operators and wallet users are strongly encouraged to upgrade ASAP.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

Notable changes
===============

Important Security Updates
--------------------------

This release contains fixes for the following security issues:

- `e7cbf1d`: Belt-and-suspenders input commitment and public key checks on MWEB inputs, providing additional defense-in-depth
during MWEB transaction validation.
- `1dcbf3f`: MWEB consensus fix addressing an input validation issue that could allow the MWEB kernel sum to become unbalanced.
This corrects MWEB input/output accounting going forward and is a required upgrade for all node operators, miners, and wallet users.
- `42e7071`: Prevent kernel fee overflow during MWEB transaction validation.
- `742ee94`: Erase block data for mutated blocks to avoid miner DoS
- `f423a84`: Miners no longer include MWEB transactions when the input and output commitments in the block would sum to zero.

MWEB stability and durability fixes
-----------------------------------

- `23e5eac`: fix data corruption issue on PMMR rewind
- `bf25a7c`, `3110a7e`: improve file write durability for MMRs

Wallet
------

- `eae9e47`: add MWEB view keys to `dumpwallet` output
- `3c3aedb`, `c882663`: fix wallet with Boost library >= 1.78
- `1cc1cee`: wallet: quick pegout accounting fix

RPC and indexing
----------------

- `455aff8`: allow `getblocktemplate` for test chains when unconnected or in IBD
- `eb7f68a`: fix an issue where transaction indexes of a block could be lost when `WriteBlock` failed after `Commit`

Build changes
-------------

- `6fc0530`: fix debug build conflict with logger symbol
- `58f89ba`: add missing `<cstdint>` include
- `dcc7bc5`: convert CRLF (Windows) line endings to LF (Linux) line endings

Test related fixes
------------------

- `0c59e99`: functional test framework fix
- `7eb181b`: functional test demonstrating handling of mutated blocks

Misc
----

- `0f5f7d5`: fix broken Transifex link from README

Credits
=======

Thanks to everyone who directly contributed to this release:

- [The Bitcoin Core Developers](https://github.com/bitcoin/bitcoin/)
- [David Burkett](https://github.com/DavidBurkett/)
- [Hector Chu](https://github.com/hectorchu)
- [Loshan](https://github.com/losh11)
- [Luke E. McKay](https://github.com/luke-mckay)
- [Soren Stoutner](https://github.com/sorenstoutner)
- [Jorge Maldonado Ventura](https://github.com/jorgesumle)
- [yujianxian](https://github.com/yujianxian)
- [AlexRadik](https://github.com/AleksandrRadik)
