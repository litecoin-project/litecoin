Litecoin Core version 0.21.5.6 is now available from:

 <https://download.litecoin.org/litecoin-0.21.5.6/>.

This is an urgent maintenance release that strengthens MWEB transaction,
block, and P2P-service validation. Upgrading is strongly recommended for all
users. Miners, pools, and MWEB service operators should upgrade before the
activation height described below.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

Notable changes
===============

MWEB security and reliability
-----------------------------

- Added a node-wide limit for expensive MWEB light-client service requests.
  This protects `getmwebleafset` and `getmwebutxos` from resource exhaustion
  across reconnecting peers while retaining normal light-client synchronization
  behavior (`cb65fc5`, `f24dec1`).
- Added relay-policy limits for MWEB transaction weight and input count before
  expensive cryptographic verification. Oversized MWEB transactions are no
  longer admitted to the mempool (`109ed13`).
- Reject invalid MWEB output public keys and safely ignore malformed MWEB
  output data during wallet scanning (`cfdfcf5`).
- Improved handling of mutated MWEB block data: descendants of a discarded
  mutated block remain processable, and peers that deliver invalid MWEB data
  through compact blocks are discouraged (`4dd6aee`, `136695e`).
- Standard relay policy now rejects kernels that signal a pegout but contain no
  pegouts (`67580d6`).

Consensus change
----------------

At mainnet height **3,154,440**, nodes running 0.21.5.6 will reject an MWEB
block containing a kernel that signals a pegout while carrying an empty pegout
list. This is a soft-forking consensus rule. The height is approximately one
week (4,032 blocks) after height 3,150,408.

Valid wallets and miners do not create this encoding. All miners and pools
should upgrade before activation to avoid producing blocks that upgraded nodes
will reject (`b250b01`).

Mining
------

- Block construction now enforces the MWEB consensus input limit, preventing
  miners from assembling oversized MWEB input sets (`dc72334`).

Tests
-----

- Expanded MWEB P2P, mining, transaction-policy, and malformed-data regression
  coverage.

Credits
=======

Thanks to everyone who directly contributed to this release:

- [David Burkett](https://github.com/DavidBurkett/)
- [DeltaXV](https://github.com/DeltaXV/)
