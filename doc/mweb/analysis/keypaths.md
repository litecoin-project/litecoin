# HD Keypaths

## bip32.cpp

### ParseHDKeypath

* scriptpubkeyman.cpp (line 428) — LegacyScriptPubKeyMan::MarkUnusedAddresses: parse stored string meta.hdKeypath when key_origin isn’t populated, so it can infer purpose/index and top up an inactive HD chain.
* scriptpubkeyman.cpp (line 479) — LegacyScriptPubKeyMan::UpgradeKeyMetadata: parse legacy meta.hdKeypath string to populate meta.key_origin.hdkeypath during metadata upgrade.
* walletdb.cpp (line 594) — wallet DB load: parse keyMeta.hdKeypath when no key origin is present, to recover chain index/purpose and update CHDChain counters.

### FormatHDKeypath

Returns the formatted keypath indices with hardened indices suffixed with an apostrophe. Example: `/0/100'/50/10'`

* pubkeyprovider.h (line 77) — OriginPubkeyProvider: build [fingerprint/path] origin prefix for descriptor strings.
* pubkeyprovider.h (line 315) — BIP32PubkeyProvider::ToString: append path to xpub in descriptor serialization.
* pubkeyprovider.h (line 326) — BIP32PubkeyProvider::ToPrivateString: append path to xprv in descriptor serialization.
* pubkeyprovider.h (lines 383-384) — BIP32PubkeyProvider::ToNormalizedString: include origin [fp/path] and end path when normalizing.
* descriptor.cpp (line 464) — MWEB descriptor ToString: include key origin prefix for the scan key when producing public/normalized descriptors.
* scriptpubkeyman.cpp (line 1987) — legacy->descriptor migration: embed key origin [fp/path] into constructed combo descriptor strings.
* scriptpubkeyman.cpp (line 2096) — legacy->descriptor migration: debug logging of script metadata key origin path.

### WriteHDKeypath

"m" + FormatHDKeypath. Example: `m/0/100'/50/10'`

* rawtransaction.cpp (line 1110) — decodepsbt RPC: serialize global xpub key origin path into global_xpubs[].path JSON.
* rawtransaction.cpp (line 1293) — decodepsbt RPC: serialize BIP32 derivation paths for input bip32_derivs[].
* rawtransaction.cpp (line 1414) — decodepsbt RPC: serialize taproot input key origins for taproot_bip32_derivs[].
* rawtransaction.cpp (line 1538) — decodepsbt RPC: serialize output bip32_derivs[] paths.
* rawtransaction.cpp (line 1582) — decodepsbt RPC: serialize output taproot taproot_bip32_derivs[] paths.
* addresses.cpp (line 630) — getaddressinfo RPC: include hdkeypath in wallet address metadata response.
* scriptpubkeyman.cpp (line 1725) — legacy wallet: persist stringified hd keypath in key metadata before DB write.
* backup.cpp (line 811) — dumpwallet RPC: emit hdkeypath comment for each dumped key.

## psbt.h

### DeserializeKeyOrigin

* psbt.h (line 184) — DeserializeHDKeypath: reads length‑prefixed key origin for a BIP32 derivation value.
* psbt.h (line 887) — PSBT input parse: decode Taproot PSBT_IN_TAP_BIP32_DERIVATION origin after leaf hashes.
* psbt.h (line 1410) — PSBT output parse: decode Taproot PSBT_OUT_TAP_BIP32_DERIVATION origin after leaf hashes.

### DeserializeHDKeypath

* psbt.h (line 205) — DeserializeHDKeypaths: read the derivation value for a pubkey keypath entry.
* psbt.h (line 2119) — PSBT global parse: read the xpub key origin for PSBT_GLOBAL_XPUB.

### DeserializeHDKeypaths

* psbt.h (line 629) — PSBT input parse: decode PSBT_IN_BIP32_DERIVATION entries into hd_keypaths.
* psbt.h (line 1316) — PSBT output parse: decode PSBT_OUT_BIP32_DERIVATION entries into hd_keypaths.

### SerializeKeyOrigin

* psbt.h (line 414) — PSBT input serialization: write Taproot PSBT_IN_TAP_BIP32_DERIVATION origin after leaf hashes.
* psbt.h (line 1217) — PSBT output serialization: write Taproot PSBT_OUT_TAP_BIP32_DERIVATION origin after leaf hashes.
* psbt.h (line 226) — SerializeHDKeypath: writes the fingerprint+path payload after its length prefix.

### SerializeHDKeypath

* psbt.h (line 238) — SerializeHDKeypaths: serialize each pubkey’s key origin for BIP32 derivation entries.
* psbt.h (line 1868) — PSBT global serialization: write PSBT_GLOBAL_XPUB value (key origin for the xpub).

### SerializeHDKeypaths

* psbt.h (line 357) — PSBT input serialization: write PSBT_IN_BIP32_DERIVATION entries.
* psbt.h (line 1171) — PSBT output serialization: write PSBT_OUT_BIP32_DERIVATION entries.
