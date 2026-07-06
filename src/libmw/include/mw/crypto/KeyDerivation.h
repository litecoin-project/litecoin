#pragma once

#include <mw/common/Macros.h>
#include <mw/models/crypto/BigInteger.h>
#include <mw/models/crypto/PublicKey.h>
#include <mw/models/crypto/SecretKey.h>
#include <mw/models/wallet/StealthAddress.h>

#include <cstdint>

MW_NAMESPACE

// Key derivation for MWEB stealth outputs (see doc/mweb/).
//
// Letter names used below:
//   a, A   - master scan secret and its pubkey A = a*G
//   b, B   - master spend secret and its pubkey B = b*G
//   bi, Bi - spend key of subaddress i: bi = b + H(T_address, i, a), Bi = bi*G
//   Ai     - scan pubkey of subaddress i: Ai = a*Bi
//   ks, Ks - sender signing key and its pubkey Ks = ks*G (published in the output)
//   n      - output nonce n = Hash128(T_nonce, ks)
//   v      - output amount
//   s      - one-time send key s = H(T_send, Ai, Bi, v, n)
//   e      - shared secret e = H(T_derive, s*Ai) = H(T_derive, a*Ke)
//   Ke     - key-exchange pubkey Ke = s*Bi (published in the output)
//   Ko     - one-time output pubkey Ko = H(T_outkey, e)*Bi (published in the output)
//
// Naming conventions:
//   Derive*  - computes a value forward from its preimage inputs. The equation is
//              the same regardless of which party runs it.
//   Recover* - reconstructs a value from the components of a published output.
//              Only possible for the holder of the required wallet secret.

//
// Forward derivations
//

//! Derives the spend key bi = b + H(T_address, i, a) of the subaddress at the given index.
SecretKey DeriveSubaddressSpendKey(const SecretKey& master_spend_secret, const SecretKey& master_scan_secret, const uint32_t index);

//! Derives the subaddress (Ai, Bi) at the given index, where Bi = B + H(T_address, i, a)*G and Ai = a*Bi.
StealthAddress DeriveSubaddress(const PublicKey& master_spend_pubkey, const SecretKey& master_scan_secret, const uint32_t index);

//! Derives the output's 128-bit secret nonce n = Hash128(T_nonce, ks) from the sender's signing key.
BigInt<16> DeriveOutputNonce(const SecretKey& sender_key);

//! Derives the output's one-time send key s = H(T_send, Ai, Bi, v, n).
SecretKey DeriveOutputSendKey(const StealthAddress& receiver_address, const uint64_t amount, const BigInt<16>& nonce);

//! Derives the shared secret e = H(T_derive, s*Ai). Sender-side forward derivation
//! (the nonce n and send key s are derived from sender_key internally).
SecretKey DeriveSharedSecret(const SecretKey& sender_key, const StealthAddress& receiver_address, const uint64_t amount);

//! Derives the output's key-exchange pubkey Ke = s*Bi.
PublicKey DeriveOutputKeyExchangePubKey(const StealthAddress& receiver_address, const SecretKey& output_send_key);

//! Derives the output's one-time pubkey Ko = H(T_outkey, e)*Bi.
PublicKey DeriveOutputPubKey(const StealthAddress& receiver_address, const SecretKey& shared_secret);

//! Derives the key that can spend the output: ko = H(T_outkey, e)*bi, so that Ko = ko*G.
SecretKey DeriveOutputSpendKey(const SecretKey& subaddress_spend_key, const SecretKey& shared_secret);

//! Derives the output's pre-switch blinding factor H(T_blind, e).
BlindingFactor DeriveOutputRawBlind(const SecretKey& shared_secret);

//! Derives the bulletproof rewind key H(T_rewind, a).
SecretKey DeriveRewindKey(const SecretKey& master_scan_secret);

//! Derives the sender signing key ks at the given index from the master scan secret.
//! ks signs the output, and its pubkey Ks = ks*G is published in the output.
SecretKey DeriveSenderSigningKey(const SecretKey& master_scan_secret, const uint64_t index);

//
// Recovery from published outputs
//

//! Recovers a published output's view tag H(T_tag, a*Ke)[0]. Requires the scan secret a.
uint8_t RecoverViewTag(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret);

//! Recovers a published output's shared secret e = H(T_derive, a*Ke). Requires the scan secret a.
SecretKey RecoverSharedSecret(const PublicKey& key_exchange_pubkey, const SecretKey& master_scan_secret);

//! Recovers the subaddress spend pubkey Bi = Ko / H(T_outkey, e) from a published output.
PublicKey RecoverSubaddressSpendPubKey(const PublicKey& output_pubkey, const SecretKey& shared_secret);

//! Recovers the subaddress (Ai, Bi) a published output was sent to, where
//! Bi = Ko / H(T_outkey, e) and Ai = a*Bi. Requires the scan secret a.
StealthAddress RecoverSubaddress(const PublicKey& output_pubkey, const SecretKey& shared_secret, const SecretKey& master_scan_secret);

END_NAMESPACE
