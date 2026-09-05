Litecoin Core version 0.21.5.7 is now available from:

 <https://download.litecoin.org/litecoin-0.21.5.7/>.

This is an urgent MWEB consensus-safety release. All miners, pools, exchanges,
MWEB service operators, and full-node users should upgrade immediately and
before the activation height described below.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

Notable changes
===============

MWEB validation
---------------

- Revalidate the complete MWEB extension block immediately before connecting
  it to chainstate, including blocks reloaded from disk during reorganization
  and crash recovery. This ensures the signatures, proofs, roots, and peg
  commitments are checked on the same body that is applied (`b4313c3`).
- Reject kernels that signal extra data but carry an empty extra-data payload
  once the consensus rule below activates (`a399fc4`, `b4313c3`).

Consensus change
----------------

At mainnet height **3,172,640**, nodes running 0.21.5.7 will reject an MWEB
block containing a kernel that signals extra data while carrying an empty
extra-data payload. This is a soft-forking consensus rule.

Valid wallets and miners do not create this encoding. All miners and pools must
upgrade before activation to avoid producing blocks that upgraded nodes will
reject.

Additional fixes
----------------

- Preserve the MWEB pegout flag in transaction undo data (`22a9162`).
- Keep precomputed transaction data alive until queued script checks finish
  during block validation (`3241370`).
- Do not return MWEB-only mempool entries to RPC clients that request the legacy
  serialization format (`d3b9ac3`).

Tests
-----

- Added regression coverage for disk-reloaded MWEB bodies with invalid kernel
  signatures, kernel roots, and peg-in identities, including checks that a
  rejected body does not modify MWEB state.

Credits
=======

Thanks to everyone who directly contributed to this release:

- [David Burkett](https://github.com/DavidBurkett/)
