Litecoin Core version 0.21.5.8 is now available from:

 <https://download.litecoin.org/litecoin-0.21.5.8/>.

This is a maintenance release that improves MWEB validation, transaction relay,
mining, and resource management. Upgrading is strongly recommended for all
users, especially miners, pools, exchanges, and MWEB service operators.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/litecoin-project/litecoin/issues>

Notable changes
===============

MWEB validation and relay
------------------------

- Improve handling of invalid MWEB block variants so that a valid block with
  the same hash can still be processed (`70ea696`).
- Defer fast relay of MWEB blocks until they have successfully connected to
  chainstate, and serialize block storage and activation to keep the stored
  and connected block bodies consistent (`0cb1419`).
- Improve rejection-cache handling so that rejected MWEB transaction variants
  do not prevent subsequent relay of valid transactions (`c07d622`).

Mining and mempool
------------------

- Validate staged MWEB transaction aggregates incrementally during block
  construction, rejecting duplicate kernels and incompatible aggregate sums
  while avoiding repeated validation of all staged transactions (`f6afd26`).
- Remove MWEB transactions that conflict with newly connected blocks, along
  with affected descendants, while preserving descendants whose parent outputs
  remain available (`36f0645`).

Resource management and networking
---------------------------------

- Release temporary cryptographic workspace when range-proof verification
  rejects invalid proofs (`d7ab03d`).
- Fix file-descriptor cleanup during POSIX file copies used by MWEB leafset
  storage, including failed copies (`b8ccaf3`).
- Update the LitecoinPool DNS seed to `dnsseed.ltcpool.org` (`63ba41f`).

Tests
-----

- Expanded regression coverage for MWEB block validation and relay, transaction
  rejection handling, aggregate block construction, mempool conflict removal,
  range-proof workspace cleanup, and leafset file-descriptor cleanup.

Credits
=======

Thanks to everyone who directly contributed to this release:

- [David Burkett](https://github.com/DavidBurkett/)
