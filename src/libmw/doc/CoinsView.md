## CoinsView

CoinsView objects give a view of the blockchain state at various lifecycles. All CoinsView objects inherit from ICoinsView, which provides APIs for retrieving UTXOs, applying updates, and building the next block.

### CoinsViewDB

Exactly one instance of CoinsViewDB is created, which represents the longest valid chain. 