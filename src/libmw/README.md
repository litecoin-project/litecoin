# libmw

Modular library for supporting Litecoin's implementation of the MWEB (Mimblewimble Extension Block). 

[Build instructions](doc/build.md)


## Design

## deps/
Contains third-party dependencies. Most of our dependencies come from vcpkg,
but here we vendor a few libraries since a suitable alternative was not found on vcpkg.

### caches/
Header-only implementations of common caching algorithms.

Repo: https://github.com/vpetrigo/caches/

### crypto/
Crypto libraries not provided by litecoin or secp256k1-zkp.

Currently, this just contains The reference implementation of blake2b.

### ghc/
A header-only implementation of the C\+\+17 std::filesystem standard, but made compatible with C\+\+11 and C\+\+14.

While boost\:\:filesystem is already pulled in by litecoin, I was uncomfortable with its API and its handling of unicode conversions.
Someone more familiar with boost::filesystem should be able to eliminate the need for this dependency.

### litecoin/
Contains utilities and basic cryptography libraries pulled from the litecoin repo.

These libraries are vendored like this as a temporary hack while libmw was being developed in a separate repo.
Now that libmw is being included in the main codebase, there's no longer a reason to copy these files here.
This directory should be removed before the first release.

### secp256k1-zkp/
The elliptic curve cryptography, including schnorr, musig, pedersen, and bulletproofs modules.

This code comes from https://github.com/mimblewimble/secp256k1-zkp,
which was built on top of https://github.com/elementsproject/secp256k1-zkp,
which was built on top of https://github.com/bitcoin/bitcoin/tree/master/src/secp256k1

Before releasing, we should see if the latest version of https://github.com/elementsproject/secp256k1-zkp contains all of the modules we need,
since it gets a lot of attention from cryptographers. Additionally, it would be wise to remove this from the deps directory,
and just replace the more-limited secp256k1 dependency that's already included in Litecoin.
Otherwise, we'll have 2 versions to maintain, and will very likely have namespace clashes to deal with.

## include/

### libmw/
This is the bridge between the internal libmw code and the existing litecoin code.

##### interfaces/
The interfaces defined here are implemented in the litecoin code and used in libmw as an alternative to callbacks.
They provide a way for the libmw code to query and update state without requiring a physical dependency on the stateful code.

###### chain_interface.h
Provides a read-only way to iterate over the current chain state.
The iterator begins at the first block since MWEB activation, and ends with the chain tip.
This is useful when validating the past MWEB state after performing a fast-sync to the horizon.

###### db_interface.h
Provides access to litecoin's leveldb instance.
Lookup is possibly by exact key, or through sequential iteration of the keys.
A batch object is also provided for updating or erasing values.