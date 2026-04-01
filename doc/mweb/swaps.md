# Bitcoin <-> MWEB Atomic Swap Process (Draft)

This document describes a trust-minimized process for swapping BTC on the Bitcoin chain for LTC in MWEB.

## 1. Scope

This is a **protocol-level** process. It is not a statement that Litecoin Core v24.x already provides all required interactive swap tooling.

Goals:
- Non-custodial swap.
- Atomic outcome: either both sides can complete, or each side has a refund path.
- No trusted third party.

Non-goals:
- UI/UX specification.
- Network transport or orderbook protocol.

## 2. MWEB Constraints That Shape The Design

MWEB kernels support fee, pegin, pegout, and absolute height lock features. MWEB does **not** provide a Bitcoin-style script engine with hashlock branches.

Implication:
- A direct "same hashlock script on both chains" HTLC is not available on MWEB.
- The MWEB leg must use a scriptless construction (joint key + pre-signed claim/refund transactions + adaptor signatures).

## 3. Parties and Notation

- `Alice`: wants to buy MWEB LTC, pays BTC.
- `Bob`: wants to sell MWEB LTC, receives BTC.
- `s`: 32-byte swap secret scalar chosen by Alice.
- `S = s*G`: adaptor point shared with Bob (without revealing `s`).
- `h = SHA256(s)`: BTC hashlock preimage hash.
- `K_swap`: jointly controlled MWEB swap pubkey (2-party aggregated key).
- `H_mweb_refund`: MWEB absolute refund height.
- `H_btc_refund`: BTC absolute/relative refund locktime (must be later than MWEB refund window by a safety margin).

Recommended timeout rule:
- `H_btc_refund` must leave enough wall-clock time after the **latest plausible MWEB claim** for Bob to learn `s`, create, relay, and confirm his BTC claim transaction.
- Because Bitcoin and Litecoin/MWEB have different block intervals, compute timeout spacing using wall-clock risk margins, then map to block heights.

## 4. Required Building Blocks

### 4.1 Bitcoin side
- A BTC lock transaction (`btc_lock`) that:
  - Lets Bob spend with `(sig_Bob, s)` where `SHA256(s) = h`.
  - Lets Alice refund after `H_btc_refund`.

### 4.2 MWEB side
- A funding transaction (`mweb_fund`) creating one swap output controlled by `K_swap`.
- Two spending transactions from that output:
  - `mweb_claim`: pays Alice (no lockheight).
  - `mweb_refund`: pays Bob with kernel `lock_height = H_mweb_refund`.

### 4.3 Scriptless atomicity link
- Bob provides Alice an **adaptor signature** for `mweb_claim` bound to `s`.
- Alice can only finalize and broadcast `mweb_claim` by using `s`.
- Once `mweb_claim` is on chain, Bob extracts `s` from the final signature and uses it to claim BTC.

## 5. Protocol Flow

### 5.1 Negotiate
1. Alice and Bob agree on:
   - BTC amount, MWEB amount, fees, confirmation targets.
   - `H_mweb_refund` and `H_btc_refund`.
2. Alice generates `s`, computes `h`, and sends `h` and `S` to Bob.

### 5.2 Build MWEB recovery path first
1. Both parties construct `mweb_fund` template and derive the swap output ID.
2. Both parties build and fully sign `mweb_refund` (locked to `H_mweb_refund`), giving Bob a valid refund transaction before BTC is locked.
3. Both parties build `mweb_claim`; Bob sends adaptor signature data (not a full usable signature by itself).
4. Alice verifies:
   - `mweb_refund` is valid and spendable by Bob after lock height.
   - adaptor data for `mweb_claim` is valid for the agreed transaction.

### 5.3 Lock BTC
1. Alice broadcasts `btc_lock` using hash `h`.
2. Bob waits for agreed BTC confirmations.

### 5.4 Lock MWEB
1. Bob broadcasts `mweb_fund`.
2. Alice waits for agreed MWEB confirmations.

### 5.5 Complete swap
1. Alice finalizes and broadcasts `mweb_claim` (uses `s` to complete signature path).
2. Bob observes `mweb_claim`, extracts `s`.
3. Bob spends `btc_lock` with `(sig_Bob, s)`.

### 5.6 Refund paths
- If Bob never broadcasts `mweb_fund`: Alice refunds BTC after `H_btc_refund`.
- If Alice never claims MWEB: Bob broadcasts `mweb_refund` at/after `H_mweb_refund`.
- If Alice claims MWEB but Bob fails to claim BTC in time: Alice refunds BTC after `H_btc_refund`.

## 6. Safety Checklist

Before Alice broadcasts `btc_lock`, she must verify:
- `mweb_refund` is fully valid and under Bob's control after its lock height.
- `H_btc_refund` is sufficiently later than `H_mweb_refund` for Bob's BTC claim safety.
- BTC script for `btc_lock` commits exactly to hash `h` and the expected refund branch.

Before Bob broadcasts `mweb_fund`, he must verify:
- `btc_lock` is confirmed enough and matches negotiated script/amount/hash.

Operational requirements for both:
- Watch both chains continuously (or use watchtowers).
- Abort if mempool policies or fees make deadlines unsafe.
- Never sign a transaction variant with different amounts, destinations, or locktimes than negotiated.

## 7. Failure Matrix

| Situation | Alice outcome | Bob outcome |
|---|---|---|
| Abort before `btc_lock` | No loss | No loss |
| `btc_lock` confirmed, `mweb_fund` absent | Refund BTC at `H_btc_refund` | No gain |
| `mweb_fund` confirmed, Alice silent | No gain | Refund MWEB at `H_mweb_refund` |
| Alice claims MWEB | Receives MWEB | Learns `s`, can claim BTC |

## 8. Implementation Notes for This Repository

What exists in current docs/code:
- MWEB kernel `HEIGHT_LOCK_FEATURE_BIT` and lock-height semantics.
- MWEB PSBTv2 key space for MWEB inputs/outputs/kernels.

What a swap implementation must add:
- Interactive 2-party signing for the MWEB swap output spend path.
- Adaptor signature support and secret extraction logic.
- Swap state machine, timeout monitoring, and chain watchers.
- RPC or daemon interfaces to coordinate BTC + MWEB legs safely.

## 9. Practical Parameters (Example Policy)

- Confirmation targets:
  - `k_btc`: 3-6 blocks (risk dependent).
  - `k_mweb`: 10+ Litecoin blocks (risk dependent).
- Timeout spacing:
  - MWEB refund window: shorter.
  - BTC refund window: longer, with additional safety margin for congestion.

Conservative policy: choose BTC refund so that even worst-case fee spikes still allow Bob to confirm his BTC claim after Alice's latest possible MWEB claim.
