# `TxState` Wallet Serialization Guide

This documents the `TxState` hierarchy, what fields each state has, and exactly how they are encoded into / decoded from the wallet database via `CWalletTx` serialization.

---

## 1. Overview

In `wallet::CWalletTx`, the on-disk “state” of a transaction is **not** stored as a tagged variant. Instead, it is encoded into two legacy fields:

- a 32-byte `block_hash`
- an `int` `index` (originally `nIndex`)

The modern code wraps this in:

```cpp
using TxState = std::variant<
    TxStateConfirmed,
    TxStateInMempool,
    TxStateConflicted,
    TxStateInactive,
    TxStateUnrecognized>;
```

and uses helper functions to convert between the variant and the `(block_hash, index)` pair:

- `TxStateSerializedBlockHash(const TxState&) -> uint256`
- `TxStateSerializedIndex(const TxState&) -> int`
- `TxStateInterpretSerialized(TxStateUnrecognized data) -> TxState`

The **wallet DB format is still “legacy”**: it only knows about `hashBlock` and `nIndex`. The `TxState` machinery is an in-memory abstraction plus a compatibility layer.

---

## 2. The `TxState` variants

### 2.1 `TxStateConfirmed`

```cpp
struct TxStateConfirmed {
    uint256 confirmed_block_hash;
    int confirmed_block_height;
    int position_in_block;

    explicit TxStateConfirmed(
        const uint256& block_hash,
        int height,
        int index)
        : confirmed_block_hash(block_hash),
          confirmed_block_height(height),
          position_in_block(index) {}
};
```

**Meaning**

- The transaction is confirmed in a known block.
- `confirmed_block_hash`: the hash of the block that includes the tx.
- `confirmed_block_height`: the height of that block (in-memory only).
- `position_in_block`: index of the tx within the block.

**Serialization**

When a `CWalletTx` is serialized:

```cpp
uint256 serializedHash = TxStateSerializedBlockHash(m_state);
int serializedIndex = TxStateSerializedIndex(m_state);
s << tx
  << serializedHash           // <-- block hash
  << dummy_vector1
  << serializedIndex          // <-- index
  << dummy_vector2
  << mapValueCopy
  << vOrderForm
  << fTimeReceivedIsTxTime
  << nTimeReceived
  << fFromMe
  << dummy_bool;
```

For a `TxStateConfirmed`:

- `TxStateSerializedBlockHash` returns `confirmed_block_hash`.
- `TxStateSerializedIndex` returns `position_in_block`.

The **height is not written** to disk at all.

**Deserialization**

On read:

```cpp
uint256 serialized_block_hash;
int serializedIndex;
s >> tx
  >> serialized_block_hash
  >> dummy_vector1
  >> serializedIndex
  >> dummy_vector2
  >> mapValue
  ...
;

m_state = TxStateInterpretSerialized({serialized_block_hash, serializedIndex});
```

For values that don’t match the “special sentinel” patterns (see below), `TxStateInterpretSerialized` says:

```cpp
} else if (data.index >= 0) {
    return TxStateConfirmed{data.block_hash, /*height=*/-1, data.index};
}
```

So:

- `confirmed_block_hash = serialized_block_hash`
- `confirmed_block_height = -1`  ← “unknown; to be filled in by sync”
- `position_in_block = serializedIndex`

That `-1` height is a deliberate sentinel meaning *“we have a hash/index but haven’t yet linked it to the current chain tip / height table”*. Gaining the actual height is the job of the wallet’s sync logic.

---

### 2.2 `TxStateInMempool`

```cpp
struct TxStateInMempool {
};
```

**Meaning**

- Transaction is currently in the mempool, unconfirmed, not known to conflict with any block.

**Fields**

- No fields; presence of this variant is the entire state.

**Serialization**

`TxStateInMempool` is **not distinguished on disk** from a non-abandoned inactive transaction:

- `TxStateSerializedBlockHash(TxStateInMempool)` → `uint256::ZERO`
- `TxStateSerializedIndex(TxStateInMempool)` → `0`

This is identical to the encoding for `TxStateInactive{abandoned = false}`.

Why? Because *mempool state is inherently ephemeral* and is recomputed on startup by rescanning the mempool and network state. The wallet file only needs to know that the tx is **not** confirmed / conflicted / abandoned; whether it’s actively in the local mempool is reconstructed.

**Deserialization**

`TxStateInterpretSerialized` interprets:

```cpp
if (data.block_hash == uint256::ZERO) {
    if (data.index == 0) return TxStateInactive{};
}
```

So `(ZERO, 0)` always comes back as:

- `TxStateInactive{abandoned = false}`

Later, when the wallet and mempool are synced, any tx that is actually in the mempool will have its in-memory state updated to `TxStateInMempool`.

---

### 2.3 `TxStateConflicted`

```cpp
struct TxStateConflicted {
    uint256 conflicting_block_hash;
    int conflicting_block_height;

    explicit TxStateConflicted(const uint256& block_hash, int height)
        : conflicting_block_hash(block_hash),
          conflicting_block_height(height) {}
};
```

**Meaning**

- Transaction is rejected because it conflicts with a confirmed block.
- `conflicting_block_hash`: the block hash whose contents conflict with this tx.
- `conflicting_block_height`: height of that block (in-memory only).

**Serialization**

For `TxStateConflicted`:

- `TxStateSerializedBlockHash` → `conflicting_block_hash`
- `TxStateSerializedIndex` → `-1`

So on disk, conflicts are encoded as “block hash + `index = -1`”.

**Deserialization**

If the encoded `index` is `-1` and the `block_hash` is *not* one of the special sentinels, `TxStateInterpretSerialized` does:

```cpp
} else if (data.index == -1) {
    return TxStateConflicted{data.block_hash, /*height=*/-1};
}
```

So deserialized fields are:

- `conflicting_block_hash = serialized_block_hash`
- `conflicting_block_height = -1` (height unknown until sync)

Again, height is not persisted; only hash and the “conflicted” tag (via `index = -1`) are.

---

### 2.4 `TxStateInactive`

```cpp
struct TxStateInactive {
    bool abandoned;

    explicit TxStateInactive(bool abandoned = false)
        : abandoned(abandoned) {}
};
```

**Meaning**

The tx is *not*:

- confirmed,
- in the mempool, or
- known to conflict with a block.

It might:

- be abandoned by the wallet user,
- have been evicted from the mempool,
- never have been broadcast,
- be conflicting with some unknown block, etc.

**Fields**

- `abandoned`: true if explicitly marked abandoned.

**Serialization**

The inactive state uses *sentinel* `(block_hash, index)` combinations:

- **Inactive, not abandoned** (`TxStateInactive{false}`):
  - `TxStateSerializedBlockHash` → `uint256::ZERO`
  - `TxStateSerializedIndex` → `0`

- **Inactive, abandoned** (`TxStateInactive{true}`):
  - `TxStateSerializedBlockHash` → `uint256::ONE`
  - `TxStateSerializedIndex` → `-1`

So:

| State                     | `block_hash`         | `index` |
|---------------------------|----------------------|---------|
| Inactive (not abandoned)  | `uint256::ZERO`      | `0`     |
| Inactive (abandoned)      | `uint256::ONE`       | `-1`    |

This encoding is baked into `TxStateSerializedBlockHash` / `TxStateSerializedIndex`.

**Deserialization**

`TxStateInterpretSerialized` treats those sentinel pairs specially:

```cpp
if (data.block_hash == uint256::ZERO) {
    if (data.index == 0) return TxStateInactive{};
} else if (data.block_hash == uint256::ONE) {
    if (data.index == -1) return TxStateInactive{/*abandoned=*/true};
}
```

Anything else falls through to either `Confirmed`, `Conflicted`, or `Unrecognized` depending on the index value.

---

### 2.5 `TxStateUnrecognized`

```cpp
struct TxStateUnrecognized {
    uint256 block_hash;
    int index;

    TxStateUnrecognized(const uint256& block_hash, int index)
        : block_hash(block_hash), index(index) {}
};
```

**Meaning**

- A raw `(block_hash, index)` pair was found in the wallet file that doesn’t match any of the known encoding patterns.
- This is a **forward-compatibility / safety net**: the wallet preserves the raw data instead of guessing, treating the tx effectively as “inactive” from a behavior standpoint, until some other event (mempool / block sync / abandonment / conflict detection) moves it into a recognized state.

**Serialization**

When serializing a `TxStateUnrecognized`:

- `TxStateSerializedBlockHash` → `block_hash`
- `TxStateSerializedIndex` → `index`

So the pair is preserved verbatim.

**Deserialization**

`TxStateInterpretSerialized` ends with:

```cpp
return data;
```

if none of the earlier patterns match, so `TxStateUnrecognized{block_hash, index}` is created.

---

## 3. The conversion helpers

### 3.1 `TxStateInterpretSerialized`

Signature:

```cpp
static inline TxState TxStateInterpretSerialized(TxStateUnrecognized data);
```

Logic in words:

1. If `block_hash == 0` and `index == 0` → **inactive, not abandoned**.
2. Else if `block_hash == 1` and `index == -1` → **inactive, abandoned**.
3. Else if `index >= 0` → **confirmed in block `block_hash` at index `index`, height = -1**.
3. Else if `index == -1` → **conflicted with block `block_hash`, height = -1**.
5. Else → **unrecognized** (keep the raw values in `TxStateUnrecognized`).

So:

- **Only two numeric fields are persisted**, and they’re overloaded to represent all 5 variants.
- `confirmed_block_height` and `conflicting_block_height` are always restored as `-1`, to be filled later by wallet sync logic that knows the current best chain.

This is why you see the `height` fields set to `-1` in the constructor calls: the on-disk format simply doesn’t contain a height, and the wallet can’t safely infer one without consulting the chain state.

---

### 3.2 `TxStateSerializedBlockHash`

```cpp
static inline uint256 TxStateSerializedBlockHash(const TxState& state)
{
    return std::visit(util::Overloaded{
        [](const TxStateInactive& inactive) {
            return inactive.abandoned ? uint256::ONE : uint256::ZERO;
        },
        [](const TxStateInMempool& in_mempool) {
            return uint256::ZERO;
        },
        [](const TxStateConfirmed& confirmed) {
            return confirmed.confirmed_block_hash;
        },
        [](const TxStateConflicted& conflicted) {
            return conflicted.conflicting_block_hash;
        },
        [](const TxStateUnrecognized& unrecognized) {
            return unrecognized.block_hash;
        }
    }, state);
}
```

Mapping:

- Inactive or InMempool → sentinel `0` or `1` hashes.
- Confirmed / Conflicted → actual block hash.
- Unrecognized → whatever was in the wallet file already.

### 3.3 `TxStateSerializedIndex`

```cpp
static inline int TxStateSerializedIndex(const TxState& state)
{
    return std::visit(util::Overloaded{
        [](const TxStateInactive& inactive) {
            return inactive.abandoned ? -1 : 0;
        },
        [](const TxStateInMempool& in_mempool) {
            return 0;
        },
        [](const TxStateConfirmed& confirmed) {
            return confirmed.position_in_block;
        },
        [](const TxStateConflicted& conflicted) {
            return -1;
        },
        [](const TxStateUnrecognized& unrecognized) {
            return unrecognized.index;
        }
    }, state);
}
```

Mapping:

- Inactive non-abandoned / InMempool → `0`
- Inactive abandoned / Conflicted → `-1`
- Confirmed → tx position in block.
- Unrecognized → raw `index`.

Together, `TxStateSerializedBlockHash` and `TxStateSerializedIndex` are the exact inverse of `TxStateInterpretSerialized` for all recognized states.

---

## 4. How `TxState` appears in the wallet DB

The relevant parts of `CWalletTx`:

```cpp
class CWalletTx
{
public:
    CTransactionRef tx;
    TxState m_state;

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        mapValue_t mapValueCopy = mapValue;
        ...
        std::vector<uint8_t> dummy_vector1; // vMerkleBranch (legacy)
        std::vector<uint8_t> dummy_vector2; // vtxPrev      (legacy)
        bool dummy_bool = false;            // fSpent       (legacy)

        uint256 serializedHash = TxStateSerializedBlockHash(m_state);
        int serializedIndex = TxStateSerializedIndex(m_state);

        s << tx
          << serializedHash
          << dummy_vector1
          << serializedIndex
          << dummy_vector2
          << mapValueCopy
          << vOrderForm
          << fTimeReceivedIsTxTime
          << nTimeReceived
          << fFromMe
          << dummy_bool;
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        Init();

        std::vector<uint256> dummy_vector1;
        std::vector<CMerkleTx> dummy_vector2;
        bool dummy_bool;
        uint256 serialized_block_hash;
        int serializedIndex;

        s >> tx
          >> serialized_block_hash
          >> dummy_vector1
          >> serializedIndex
          >> dummy_vector2
          >> mapValue
          >> vOrderForm
          >> fTimeReceivedIsTxTime
          >> nTimeReceived
          >> fFromMe
          >> dummy_bool;

        m_state = TxStateInterpretSerialized({serialized_block_hash, serializedIndex});
        ...
    }
};
```

**Key points:**

- The on-disk layout keeps the legacy fields in place:
  - `tx`
  - `hashBlock` (now `serializedHash`)
  - `vMerkleBranch` (dummy)
  - `nIndex` (now `serializedIndex`)
  - `vtxPrev` (dummy)
  - plus the rest of the usual wallet metadata.
- `TxState` is **only represented on disk through `hashBlock` and `nIndex`**.
- Heights are reconstructed in-memory from the chain state and are always written as `-1` initially when the state is reconstructed from disk.

---

## 5. `SyncTxState`

There’s another variant alias:

```cpp
using SyncTxState = std::variant<
    TxStateConfirmed,
    TxStateInMempool,
    TxStateInactive>;
```

This is a **restricted** subset of states that the “transaction sync logic” operates on. In other words, the sync code assumes it’s only dealing with:

- confirmed,
- mempool,
- or inactive (abandoned/non-abandoned),

and not directly with:

- conflicted, or
- unrecognized.

Internally, when conflicts are detected or odd legacy encodings are encountered, the full `TxState` variant is used; `SyncTxState` is just the view the synchronization algorithm is willing to reason about.

---

## 6. Quick reference tables

### 6.1 `TxState` → `(block_hash, index)` on disk

| TxState variant           | Fields used                              | `block_hash` written           | `index` written | Notes                                                |
|---------------------------|-------------------------------------------|--------------------------------|-----------------|------------------------------------------------------|
| `TxStateConfirmed`        | `confirmed_block_hash`, `position_in_block` | `confirmed_block_hash`        | `position_in_block` | Height **not** stored; set to `-1` on load          |
| `TxStateInMempool`       | _none_                                   | `uint256::ZERO`               | `0`             | Collides with non-abandoned `Inactive`              |
| `TxStateConflicted`      | `conflicting_block_hash`                 | `conflicting_block_hash`      | `-1`            | Height **not** stored; set to `-1` on load          |
| `TxStateInactive{false}` | `abandoned = false`                      | `uint256::ZERO`               | `0`             | Same encoding as `InMempool`                        |
| `TxStateInactive{true}`  | `abandoned = true`                       | `uint256::ONE`                | `-1`            | “Abandoned” sentinel pair                           |
| `TxStateUnrecognized`    | `block_hash`, `index`                    | `block_hash` (unchanged)      | `index`         | Raw values preserved                                |

### 6.2 `(block_hash, index)` on disk → `TxState` on load

| Condition                                      | Resulting `TxState`                                             |
|------------------------------------------------|------------------------------------------------------------------|
| `block_hash == 0` and `index == 0`            | `TxStateInactive{abandoned = false}`                            |
| `block_hash == 1` and `index == -1`           | `TxStateInactive{abandoned = true}`                             |
| `block_hash ∉ {0, 1}` and `index >= 0`        | `TxStateConfirmed{block_hash, height = -1, index}`              |
| `block_hash ∉ {0, 1}` and `index == -1`       | `TxStateConflicted{block_hash, height = -1}`                    |
| anything else                                  | `TxStateUnrecognized{block_hash, index}`                        |

---

That’s the whole dance: two legacy fields on disk, a handful of sentinel pairs, and a modern typed variant on top. As long as nobody “optimizes away” the weird `-1` heights or the `0/1` sentinel hashes, old wallets remain readable and new code can reason about tx state in a sane, type-safe way.
