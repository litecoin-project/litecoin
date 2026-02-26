# Quantum Resistance

**TL;DR:** When the time comes, we'll be able to transition the MWEB to quantum-resistant cryptography following a similar process and similar security guarantees as we have with traditional LTC addresses.

## Background

Elliptic curve cryptography (ECC), like the kind used in Bitcoin, uses a special kind of math involving points along two dimensional curves that can be "added" together. We'll be representing curve points using capital letters and scalars (integers) using lowercase letters.

Wallet addresses are derived from a public key (`P`, a curve point), which is calculated from a private key (`k`, a scalar). `P` is nothing more than `k` times a special point `G` on the curve, called the generator point. This is written as: `P = k*G`.

![ECC](https://i.ytimg.com/vi/Xem-AjUBOkU/maxresdefault.jpg)

In normal computing, it's easy to calculate `P` from `k`, but it's infeasible to calculate `k` from `P`. This is the entire basis of ECC security, known as the elliptic curve discrete logarithm problem (ECDLP).

Unfortunately, quantum computers operate in a mind-bending way that allows them to solve certain problems much faster than classical computers. One of these problems is the ECDLP, which means that quantum computers could theoretically break ECC-based systems like Bitcoin & Litecoin.


## Pedersen Commitments

MWEB doesn't use addresses, but instead uses something called Pedersen Commitments. These are a kind of cryptographic commitment that hides the value being committed to, while still allowing it to be verified. They're used in the MWEB to hide the amounts being sent in transactions.

Similar to typical addresses, Pedersen Commitments are a curve point `C`, but are not just calculated from a single scalar and generator point. Instead, a commitment is derived from a private key or "blinding factor" `r` and a value `v` using 2 special generator points, `G` and `H`. A commitment is calculated as: `C = v*H + r*G`. You can read more [here](https://docs.grin.mw/wiki/introduction/mimblewimble/mimblewimble/) about how Pedersen Commitments are used in Mimblewimble.


### Perfectly Hiding, Computationally Binding

The security of Pedersen Commitments relies on the relationship between `H` and `G` being unknown. In other words, there is an `x` such that `x*H = G`, but that `x` is not known.

Pedersen Commitments are "perfectly hiding," meaning no one can ever look at a single commitment and uncover its secret value. But they're only "computationally binding," which means that, with quantum computing magic, you could potentially produce two different (value, blinding factor) pairs that open the same commitment.

To understand what that means, imagine a malicious actor has an unspent output with commitment `C = v*H + r*G`. If `x` is learned by the attacker, they could derive a new blinding factor `r' = r - i*x` allowing them to "change" the value to `v' = v + i`, which still gives them the same commitment. That is `C = v*H + r*G = v'*H + r'*G`. This would allow the attacker to create `i` new coins out of thin air.


## Switch Commitments

For MWEB, we use a special technique when calculating the blinding factors for Pedersen Commitments that allows us to later "switch" to a different type of commitment called "ElGamal Commitments."

In practice, what this means is that whenever we deem it necessary to switch to a quantum-resistant signature scheme, we can start to require a stricter proof when spending existing coins that will prevent the inflation attack described above.

Switch commitments are explained elegantly [here](https://docs.grin.mw/wiki/miscellaneous/switch-commitments/) and in much more detail [here](https://eprint.iacr.org/2017/237.pdf).


## Summary

While MWEB, like traditional Bitcoin/Litecoin addresses, is vulnerable to quantum attacks, our forward-thinking commitment design allows us a safe path forward for migrating to a quantum-resistant signature scheme when we deem it necessary, while avoiding the risk of inflation, and without automatically revealing the values of old coins.

When the time comes to switch to quantum-resistant cryptography (and fortunately, we should have plenty of warning), we will be able to this with MWEB the same way we do with traditional LTC addresses.

So as long as we "flip the switch" to activate the stricter ElGamal commitment proofs in a timely manner, we avoid any risk of inflating the money supply.

