Litecoin Core version 0.21.4 is now available from:

 <https://download.litecoin.org/litecoin-0.21.4/>.

This is a new patch version release that includes, new features and important security updates.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

Notable changes
===============

Important Security Updates
--------------------------

This release contains fixes for the following security vulnerabilities:

- [CVE-2024-35202](https://www.cvedetails.com/cve/CVE-2024-35202/),
which allows remote attackers to cause a denial of service (blocktxn message-handling assertion and node exit)
by including transactions in a blocktxn message that are not committed to in a block's merkle root.
FillBlock can be called twice for one PartiallyDownloadedBlock instance.
  - `5d4a2e5`: backported from Bitcoin Core (`a8897f6`)

- [Hindered block propagation due to mutated blocks](https://bitcoincore.org/en/2024/10/08/disclose-mutated-blocks-hindering-propagation/),
where a peer could send mutated blocks which could clear the download state of other peers that also announced block, hindering block propagation.
  - `dab3bb7`: backported from Bitcoin Core (`dbfc748`)

- [Infinite loop bug in miniupnp dependency](https://bitcoincore.org/en/2024/07/31/disclose-upnp-oom/),
which could be exploited by an attacker on the local network to trigger an OOM.
  - `16ba8b8`: backported from Bitcoin Core (`fa2a5b8`)

Bug fixes
---------
- `0d04e75`: default -peerblockfilters and -blockfilterindex to off when pruning is enabled

Test related fixes
------------------
- `7d9fea0`: fix functional tests that were broken by changes in 0.21.3

Credits
=======

Thanks to everyone who directly contributed to this release:

- [The Bitcoin Core Developers](https://github.com/bitcoin/bitcoin/)
- [David Burkett](https://github.com/DavidBurkett/)
- [Hector Chu](https://github.com/hectorchu)
- [Loshan](https://github.com/losh11)