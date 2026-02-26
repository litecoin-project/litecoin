### Rewindable Payloads

1. Shared payload: for single-commit proofs, the value plus optional 20‑byte `ProofMessage` are mixed into alpha using the `shared_nonce`, and can be recovered as a 32‑byte `shared_msg` when rewinding. Layout is 4 zero bytes + 20‑byte message + 8‑byte value (big‑endian).

2. Private (rewindable) payload: the `private_nonce` lets the rewind path recover the blinding factor (taux) and returns bytes 4..31 (28 bytes) as private_msg. There’s a TODO noting this should be a real private message, not the blinding factor.

Nonce derivation in our code: `Output::Create` uses SecretKey::Random() for both sharedNonce and privateNonce, and passes an empty ProofMessage{}; there is no deterministic derivation to “restore” them unless you persist them yourself.


=======

Knowing the blinding factor does not let the receiver derive shared_nonce or private_nonce unless you define those nonces as a deterministic function of something the receiver already knows.

Details tied to the implementation:

* `shared_nonce` and `private_nonce` are independent 32‑byte seeds into `secp256k1_scalar_chacha20` (`alpha`/`rho` `from shared_nonce`, `tau1`/`tau2` from `private_nonce`). There’s no reverse mapping from the proof or blinding factor back to those seeds.
* The rewind API expects the actual nonces to recover the shared/private payloads; it doesn’t attempt to compute them from the commitment or blinding factor.
* The blinding factor used in the commitment is derived from the shared secret `e` via `OutputMask::FromShared` and `BlindSwitch`, but that’s separate from the Bulletproof nonces.
* Today the sender uses random nonces (`SecretKey::Random()`), so there’s nothing for the receiver to deterministically recompute.
* If you want the receiver to recover the payloads deterministically, you’d need to define:
    - `shared_nonce = H(tag || shared_secret)` or similar, so scan‑key holders can recompute it after identifying the output.
    - `private_nonce` likewise, if you want the receiver to read the private payload too. But that means anyone who can derive the same secret (e.g., all scan‑key holders) can read it.


