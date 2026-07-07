// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PSBT_H
#define BITCOIN_PSBT_H

#include <node/transaction.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/keyorigin.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <span.h>
#include <streams.h>
#include <util/result.h>

#include <bitset>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>

// Magic bytes
static constexpr uint8_t PSBT_MAGIC_BYTES[5] = {'p', 's', 'b', 't', 0xff};

// Global types
static constexpr uint8_t PSBT_GLOBAL_UNSIGNED_TX = 0x00;
static constexpr uint8_t PSBT_GLOBAL_XPUB = 0x01;
static constexpr uint8_t PSBT_GLOBAL_TX_VERSION = 0x02;
static constexpr uint8_t PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03;
static constexpr uint8_t PSBT_GLOBAL_INPUT_COUNT = 0x04;
static constexpr uint8_t PSBT_GLOBAL_OUTPUT_COUNT = 0x05;
static constexpr uint8_t PSBT_GLOBAL_TX_MODIFIABLE = 0x06;
static constexpr uint8_t PSBT_GLOBAL_MWEB_TX_OFFSET = 0x90;
static constexpr uint8_t PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET = 0x91;
static constexpr uint8_t PSBT_GLOBAL_MWEB_KERNEL_COUNT = 0x92;
static constexpr uint8_t PSBT_GLOBAL_VERSION = 0xFB;
static constexpr uint8_t PSBT_GLOBAL_PROPRIETARY = 0xFC;

// Kernel types
static constexpr uint8_t PSBT_KERN_EXCESS_COMMIT = 0x00;
static constexpr uint8_t PSBT_KERN_STEALTH_COMMIT = 0x01;
static constexpr uint8_t PSBT_KERN_FEE = 0x02;
static constexpr uint8_t PSBT_KERN_PEGIN_AMOUNT = 0x03;
static constexpr uint8_t PSBT_KERN_PEGOUT = 0x04;
static constexpr uint8_t PSBT_KERN_LOCK_HEIGHT = 0x05;
static constexpr uint8_t PSBT_KERN_FEATURES = 0x06;
static constexpr uint8_t PSBT_KERN_EXTRA_DATA = 0x07;
static constexpr uint8_t PSBT_KERN_SIG = 0x08;
static constexpr uint8_t PSBT_KERN_PROPRIETARY = 0xFC;

// Input types
static constexpr uint8_t PSBT_IN_NON_WITNESS_UTXO = 0x00;
static constexpr uint8_t PSBT_IN_WITNESS_UTXO = 0x01;
static constexpr uint8_t PSBT_IN_PARTIAL_SIG = 0x02;
static constexpr uint8_t PSBT_IN_SIGHASH = 0x03;
static constexpr uint8_t PSBT_IN_REDEEMSCRIPT = 0x04;
static constexpr uint8_t PSBT_IN_WITNESSSCRIPT = 0x05;
static constexpr uint8_t PSBT_IN_BIP32_DERIVATION = 0x06;
static constexpr uint8_t PSBT_IN_SCRIPTSIG = 0x07;
static constexpr uint8_t PSBT_IN_SCRIPTWITNESS = 0x08;
static constexpr uint8_t PSBT_IN_RIPEMD160 = 0x0A;
static constexpr uint8_t PSBT_IN_SHA256 = 0x0B;
static constexpr uint8_t PSBT_IN_HASH160 = 0x0C;
static constexpr uint8_t PSBT_IN_HASH256 = 0x0D;
static constexpr uint8_t PSBT_IN_PREVIOUS_TXID = 0x0E;
static constexpr uint8_t PSBT_IN_OUTPUT_INDEX = 0x0F;
static constexpr uint8_t PSBT_IN_SEQUENCE = 0x10;
static constexpr uint8_t PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11;
static constexpr uint8_t PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12;
static constexpr uint8_t PSBT_IN_TAP_KEY_SIG = 0x13;
static constexpr uint8_t PSBT_IN_TAP_SCRIPT_SIG = 0x14;
static constexpr uint8_t PSBT_IN_TAP_LEAF_SCRIPT = 0x15;
static constexpr uint8_t PSBT_IN_TAP_BIP32_DERIVATION = 0x16;
static constexpr uint8_t PSBT_IN_TAP_INTERNAL_KEY = 0x17;
static constexpr uint8_t PSBT_IN_TAP_MERKLE_ROOT = 0x18;
static constexpr uint8_t PSBT_IN_MWEB_OUTPUT_ID = 0x90;
static constexpr uint8_t PSBT_IN_MWEB_COMMIT = 0x91;
static constexpr uint8_t PSBT_IN_MWEB_OUTPUT_PUBKEY = 0x92;
static constexpr uint8_t PSBT_IN_MWEB_INPUT_PUBKEY = 0x93;
static constexpr uint8_t PSBT_IN_MWEB_FEATURES = 0x94;
static constexpr uint8_t PSBT_IN_MWEB_INPUT_SIG = 0x95;
static constexpr uint8_t PSBT_IN_MWEB_ADDR_DESCRIPTOR = 0x96;
static constexpr uint8_t PSBT_IN_MWEB_AMOUNT = 0x97;
static constexpr uint8_t PSBT_IN_MWEB_SHARED_SECRET = 0x98;
static constexpr uint8_t PSBT_IN_MWEB_KEY_EXCHANGE_PK = 0x99;
static constexpr uint8_t PSBT_IN_MWEB_EXTRA_DATA = 0x9C;
static constexpr uint8_t PSBT_IN_PROPRIETARY = 0xFC;

// Output types
static constexpr uint8_t PSBT_OUT_REDEEMSCRIPT = 0x00;
static constexpr uint8_t PSBT_OUT_WITNESSSCRIPT = 0x01;
static constexpr uint8_t PSBT_OUT_BIP32_DERIVATION = 0x02;
static constexpr uint8_t PSBT_OUT_AMOUNT = 0x03;
static constexpr uint8_t PSBT_OUT_SCRIPT = 0x04;
static constexpr uint8_t PSBT_OUT_TAP_INTERNAL_KEY = 0x05;
static constexpr uint8_t PSBT_OUT_TAP_TREE = 0x06;
static constexpr uint8_t PSBT_OUT_TAP_BIP32_DERIVATION = 0x07;
static constexpr uint8_t PSBT_OUT_MWEB_STEALTH_ADDRESS = 0x90;
static constexpr uint8_t PSBT_OUT_MWEB_COMMIT = 0x91;
static constexpr uint8_t PSBT_OUT_MWEB_FEATURES = 0x92;
static constexpr uint8_t PSBT_OUT_MWEB_SENDER_PUBKEY = 0x93;
static constexpr uint8_t PSBT_OUT_MWEB_OUTPUT_PUBKEY = 0x94;
static constexpr uint8_t PSBT_OUT_MWEB_STANDARD_FIELDS = 0x95;
static constexpr uint8_t PSBT_OUT_MWEB_RANGEPROOF = 0x96;
static constexpr uint8_t PSBT_OUT_MWEB_SIG = 0x97;
static constexpr uint8_t PSBT_OUT_MWEB_EXTRA_DATA = 0x98;
static constexpr uint8_t PSBT_OUT_PROPRIETARY = 0xFC;

// The separator is 0x00. Reading this in means that the unserializer can interpret it
// as a 0 length key which indicates that this is the separator. The separator has no value.
static constexpr uint8_t PSBT_SEPARATOR = 0x00;

// BIP 174 does not specify a maximum file size, but we set a limit anyway
// to prevent reading a stream indefinitely and running out of memory.
const std::streamsize MAX_FILE_SIZE_PSBT = 100000000; // 100 MB

// PSBT version number
static constexpr uint32_t PSBT_HIGHEST_VERSION = 2;

/** A structure for PSBT proprietary types */
struct PSBTProprietary
{
    uint64_t subtype;
    std::vector<unsigned char> identifier;
    std::vector<unsigned char> key;
    std::vector<unsigned char> value;

    bool operator<(const PSBTProprietary &b) const {
        return key < b.key;
    }
    bool operator==(const PSBTProprietary &b) const {
        return key == b.key;
    }
};

// Takes a stream and multiple arguments and serializes them as if first serialized into a vector and then into the stream
// The resulting output into the stream has the total serialized length of all of the objects followed by all objects concatenated with each other.
template<typename Stream, typename... X>
void SerializeToVector(Stream& s, const X&... args)
{
    WriteCompactSize(s, GetSerializeSizeMany(s.GetVersion(), args...));
    SerializeMany(s, args...);
}

// Takes a stream and multiple arguments and unserializes them first as a vector then each object individually in the order provided in the arguments
template<typename Stream, typename... X>
void UnserializeFromVector(Stream& s, X&... args)
{
    size_t expected_size = ReadCompactSize(s);
    size_t remaining_before = s.size();
    UnserializeMany(s, args...);
    size_t remaining_after = s.size();
    if (remaining_after + expected_size != remaining_before) {
        throw std::ios_base::failure("Size of value was not the stated size");
    }
}

// Deserialize bytes of given length from the stream as a KeyOriginInfo
template<typename Stream>
KeyOriginInfo DeserializeKeyOrigin(Stream& s, uint64_t length)
{
    // Read in key path
    if (length % 4 || length == 0) {
        throw std::ios_base::failure("Invalid length for HD key path");
    }

    KeyOriginInfo hd_keypath;
    s >> hd_keypath.fingerprint;
    for (unsigned int i = 4; i < length; i += sizeof(uint32_t)) {
        uint32_t index;
        s >> index;
        hd_keypath.hdkeypath.path.push_back(index);
    }
    return hd_keypath;
}

// Deserialize a length prefixed KeyOriginInfo from a stream
template<typename Stream>
void DeserializeHDKeypath(Stream& s, KeyOriginInfo& hd_keypath)
{
    hd_keypath = DeserializeKeyOrigin(s, ReadCompactSize(s));
}

// Deserialize HD keypaths into a map
template<typename Stream>
void DeserializeHDKeypaths(Stream& s, const std::vector<unsigned char>& key, std::map<CPubKey, KeyOriginInfo>& hd_keypaths)
{
    // Make sure that the key is the size of pubkey + 1
    if (key.size() != CPubKey::SIZE + 1 && key.size() != CPubKey::COMPRESSED_SIZE + 1) {
        throw std::ios_base::failure("Size of key was not the expected size for the type BIP32 keypath");
    }
    // Read in the pubkey from key
    CPubKey pubkey(key.begin() + 1, key.end());
    if (!pubkey.IsFullyValid()) {
       throw std::ios_base::failure("Invalid pubkey");
    }
    if (hd_keypaths.count(pubkey) > 0) {
        throw std::ios_base::failure("Duplicate Key, pubkey derivation path already provided");
    }

    KeyOriginInfo keypath;
    DeserializeHDKeypath(s, keypath);

    // Add to map
    hd_keypaths.emplace(pubkey, std::move(keypath));
}

// Serialize a KeyOriginInfo to a stream
template<typename Stream>
void SerializeKeyOrigin(Stream& s, KeyOriginInfo key_origin)
{
    s << key_origin.fingerprint;
    for (const auto& path : key_origin.hdkeypath.path) {
        s << path;
    }
}

// Serialize a length prefixed KeyOriginInfo to a stream
template<typename Stream>
void SerializeHDKeypath(Stream& s, KeyOriginInfo key_origin)
{
    WriteCompactSize(s, (key_origin.hdkeypath.path.size() + 1) * sizeof(uint32_t));
    SerializeKeyOrigin(s, key_origin);
}

// Serialize HD keypaths to a stream from a map
template<typename Stream>
void SerializeHDKeypaths(Stream& s, const std::map<CPubKey, KeyOriginInfo>& hd_keypaths, CompactSizeWriter type)
{
    for (const auto& keypath_pair : hd_keypaths) {
        if (!keypath_pair.first.IsValid()) {
            throw std::ios_base::failure("Invalid CPubKey being serialized");
        }
        SerializeToVector(s, type, Span{keypath_pair.first});
        SerializeHDKeypath(s, keypath_pair.second);
    }
}

/** A structure for PSBTs which contain per-input information */
struct PSBTInput
{
    CTransactionRef non_witness_utxo;
    CTxOut witness_utxo;
    CScript redeem_script;
    CScript witness_script;
    CScript final_script_sig;
    CScriptWitness final_script_witness;
    std::map<CPubKey, KeyOriginInfo> hd_keypaths;
    std::map<CKeyID, SigPair> partial_sigs;
    std::map<uint160, std::vector<unsigned char>> ripemd160_preimages;
    std::map<uint256, std::vector<unsigned char>> sha256_preimages;
    std::map<uint160, std::vector<unsigned char>> hash160_preimages;
    std::map<uint256, std::vector<unsigned char>> hash256_preimages;

    uint256 prev_txid;
    std::optional<uint32_t> prev_out;
    std::optional<uint32_t> sequence;
    std::optional<uint32_t> time_locktime;
    std::optional<uint32_t> height_locktime;

    // Taproot fields
    std::vector<unsigned char> m_tap_key_sig;
    std::map<std::pair<XOnlyPubKey, uint256>, std::vector<unsigned char>> m_tap_script_sigs;
    std::map<std::pair<CScript, int>, std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>> m_tap_scripts;
    std::map<XOnlyPubKey, std::pair<std::set<uint256>, KeyOriginInfo>> m_tap_bip32_paths;
    XOnlyPubKey m_tap_internal_key;
    uint256 m_tap_merkle_root;

    // MWEB fields
    std::optional<mw::Hash> mweb_output_id;
    std::optional<Commitment> mweb_output_commit;
    std::optional<PublicKey> mweb_output_pubkey;
    std::optional<PublicKey> mweb_input_pubkey;
    std::optional<uint8_t> mweb_features;
    std::optional<Signature> mweb_sig;
    std::optional<CAmount> mweb_amount;
    std::optional<SecretKey> mweb_shared_secret;
    std::optional<PublicKey> mweb_key_exchange_pubkey;
    std::vector<uint8_t> mweb_extra_data;
    std::optional<std::string> mweb_address_descriptor;

    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;
    std::set<PSBTProprietary> m_proprietary;
    std::optional<int> sighash_type;

    uint32_t m_psbt_version;

    AnyOutputID GetID() const
    {
        if (mweb_output_id.has_value()) {
            return AnyOutputID{*mweb_output_id};
        } else {
            return AnyOutputID(COutPoint(prev_txid, prev_out.value_or(0)));
        }
    }

    bool IsNull() const;
    bool IsMWEB() const noexcept { return mweb_output_id.has_value(); }
    void FillSignatureData(SignatureData& sigdata) const;
    void FromSignatureData(const SignatureData& sigdata);
    void Merge(const PSBTInput& input);
    /**
     * Retrieves the UTXO for this input
     *
     * @param[out] utxo The UTXO of this input
     * @return Whether the UTXO could be retrieved
     */
    bool GetUTXO(CTxOut& utxo) const;
    COutPoint GetOutPoint() const;
    PSBTInput(uint32_t psbt_version) : m_psbt_version(psbt_version) {}

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        // Write the utxo
        if (non_witness_utxo) {
            SerializeToVector(s, CompactSizeWriter(PSBT_IN_NON_WITNESS_UTXO));
            OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS);
            SerializeToVector(os, non_witness_utxo);
        }
        if (!witness_utxo.IsNull()) {
            SerializeToVector(s, CompactSizeWriter(PSBT_IN_WITNESS_UTXO));
            SerializeToVector(s, witness_utxo);
        }

        if (final_script_sig.empty() && final_script_witness.IsNull()) {
            // Write any partial signatures
            for (const auto& sig_pair : partial_sigs) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_PARTIAL_SIG), Span{sig_pair.second.first});
                s << sig_pair.second.second;
            }

            // Write the sighash type
            if (sighash_type != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_SIGHASH));
                SerializeToVector(s, *sighash_type);
            }

            // Write the redeem script
            if (!redeem_script.empty()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_REDEEMSCRIPT));
                s << redeem_script;
            }

            // Write the witness script
            if (!witness_script.empty()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_WITNESSSCRIPT));
                s << witness_script;
            }

            // Write any hd keypaths
            SerializeHDKeypaths(s, hd_keypaths, CompactSizeWriter(PSBT_IN_BIP32_DERIVATION));

            // Write any ripemd160 preimage
            for (const auto& [hash, preimage] : ripemd160_preimages) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_RIPEMD160), Span{hash});
                s << preimage;
            }

            // Write any sha256 preimage
            for (const auto& [hash, preimage] : sha256_preimages) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_SHA256), Span{hash});
                s << preimage;
            }

            // Write any hash160 preimage
            for (const auto& [hash, preimage] : hash160_preimages) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_HASH160), Span{hash});
                s << preimage;
            }

            // Write any hash256 preimage
            for (const auto& [hash, preimage] : hash256_preimages) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_HASH256), Span{hash});
                s << preimage;
            }

            // Write taproot key sig
            if (!m_tap_key_sig.empty()) {
                SerializeToVector(s, PSBT_IN_TAP_KEY_SIG);
                s << m_tap_key_sig;
            }

            // Write taproot script sigs
            for (const auto& [pubkey_leaf, sig] : m_tap_script_sigs) {
                const auto& [xonly, leaf_hash] = pubkey_leaf;
                SerializeToVector(s, PSBT_IN_TAP_SCRIPT_SIG, xonly, leaf_hash);
                s << sig;
            }

            // Write taproot leaf scripts
            for (const auto& [leaf, control_blocks] : m_tap_scripts) {
                const auto& [script, leaf_ver] = leaf;
                for (const auto& control_block : control_blocks) {
                    SerializeToVector(s, PSBT_IN_TAP_LEAF_SCRIPT, Span{control_block});
                    std::vector<unsigned char> value_v(script.begin(), script.end());
                    value_v.push_back((uint8_t)leaf_ver);
                    s << value_v;
                }
            }

            // Write taproot bip32 keypaths
            for (const auto& [xonly, leaf_origin] : m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                SerializeToVector(s, PSBT_IN_TAP_BIP32_DERIVATION, xonly);
                std::vector<unsigned char> value;
                CVectorWriter s_value(s.GetType(), s.GetVersion(), value, 0);
                s_value << leaf_hashes;
                SerializeKeyOrigin(s_value, origin);
                s << value;
            }

            // Write taproot internal key
            if (!m_tap_internal_key.IsNull()) {
                SerializeToVector(s, PSBT_IN_TAP_INTERNAL_KEY);
                s << ToByteVector(m_tap_internal_key);
            }

            // Write taproot merkle root
            if (!m_tap_merkle_root.IsNull()) {
                SerializeToVector(s, PSBT_IN_TAP_MERKLE_ROOT);
                SerializeToVector(s, m_tap_merkle_root);
            }
        }

        // Write script sig
        if (!final_script_sig.empty()) {
            SerializeToVector(s, CompactSizeWriter(PSBT_IN_SCRIPTSIG));
            s << final_script_sig;
        }
        // write script witness
        if (!final_script_witness.IsNull()) {
            SerializeToVector(s, CompactSizeWriter(PSBT_IN_SCRIPTWITNESS));
            SerializeToVector(s, final_script_witness.stack);
        }

        // Write PSBTv2 fields
        if (m_psbt_version >= 2) {
            // Write prev txid, vout, sequence, and lock times
            if (!prev_txid.IsNull()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_PREVIOUS_TXID));
                SerializeToVector(s, prev_txid);
            }
            if (prev_out != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_OUTPUT_INDEX));
                SerializeToVector(s, *prev_out);
            }
            if (sequence != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_SEQUENCE));
                SerializeToVector(s, *sequence);
            }
            if (time_locktime != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_REQUIRED_TIME_LOCKTIME));
                SerializeToVector(s, *time_locktime);
            }
            if (height_locktime != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME));
                SerializeToVector(s, *height_locktime);
            }

            // MWEB fields
            if (mweb_output_id != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_OUTPUT_ID));
                SerializeToVector(s, *mweb_output_id);
            }
            if (mweb_output_commit != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_COMMIT));
                SerializeToVector(s, *mweb_output_commit);
            }
            if (mweb_output_pubkey != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_OUTPUT_PUBKEY));
                SerializeToVector(s, *mweb_output_pubkey);
            }
            if (mweb_input_pubkey != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_INPUT_PUBKEY));
                SerializeToVector(s, *mweb_input_pubkey);
            }
            if (mweb_features != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_FEATURES));
                SerializeToVector(s, *mweb_features);
            }
            if (!mweb_extra_data.empty()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_EXTRA_DATA));
                s << mweb_extra_data;
            }
            if (mweb_sig != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_INPUT_SIG));
                SerializeToVector(s, *mweb_sig);
            }
            if (mweb_address_descriptor != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_ADDR_DESCRIPTOR));
                const std::vector<unsigned char> descriptor_bytes(mweb_address_descriptor->begin(), mweb_address_descriptor->end());
                s << descriptor_bytes;
            }
            if (mweb_amount != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_AMOUNT));
                SerializeToVector(s, *mweb_amount);
            }
            if (mweb_shared_secret != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_SHARED_SECRET));
                SerializeToVector(s, *mweb_shared_secret);
            }
            if (mweb_key_exchange_pubkey != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_IN_MWEB_KEY_EXCHANGE_PK));
                SerializeToVector(s, *mweb_key_exchange_pubkey);
            }
        }

        // Write proprietary things
        for (const auto& entry : m_proprietary) {
            s << entry.key;
            s << entry.value;
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Used for duplicate key detection
        std::set<std::vector<unsigned char>> key_lookup;

        // Read loop
        bool found_sep = false;
        while(!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // Type is compact size uint at beginning of key
            SpanReader skey(s.GetType(), s.GetVersion(), key);
            uint64_t type = ReadCompactSize(skey);

            // Do stuff based on type
            switch(type) {
                case PSBT_IN_NON_WITNESS_UTXO:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input non-witness utxo already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Non-witness utxo key is more than one byte type");
                    }
                    // Set the stream to unserialize with witness since this is always a valid network transaction
                    OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() & ~SERIALIZE_TRANSACTION_NO_WITNESS);
                    UnserializeFromVector(os, non_witness_utxo);
                    break;
                }
                case PSBT_IN_WITNESS_UTXO:
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input witness utxo already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Witness utxo key is more than one byte type");
                    }
                    UnserializeFromVector(s, witness_utxo);
                    break;
                case PSBT_IN_PARTIAL_SIG:
                {
                    // Make sure that the key is the size of pubkey + 1
                    if (key.size() != CPubKey::SIZE + 1 && key.size() != CPubKey::COMPRESSED_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type partial signature pubkey");
                    }
                    // Read in the pubkey from key
                    CPubKey pubkey(key.begin() + 1, key.end());
                    if (!pubkey.IsFullyValid()) {
                       throw std::ios_base::failure("Invalid pubkey");
                    }
                    if (partial_sigs.count(pubkey.GetID()) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input partial signature for pubkey already provided");
                    }

                    // Read in the signature from value
                    std::vector<unsigned char> sig;
                    s >> sig;

                    // Add to list
                    partial_sigs.emplace(pubkey.GetID(), SigPair(pubkey, std::move(sig)));
                    break;
                }
                case PSBT_IN_SIGHASH:
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input sighash type already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Sighash type key is more than one byte type");
                    }
                    int sighash;
                    UnserializeFromVector(s, sighash);
                    sighash_type = sighash;
                    break;
                case PSBT_IN_REDEEMSCRIPT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input redeemScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input redeemScript key is more than one byte type");
                    }
                    s >> redeem_script;
                    break;
                }
                case PSBT_IN_WITNESSSCRIPT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input witnessScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input witnessScript key is more than one byte type");
                    }
                    s >> witness_script;
                    break;
                }
                case PSBT_IN_BIP32_DERIVATION:
                {
                    DeserializeHDKeypaths(s, key, hd_keypaths);
                    break;
                }
                case PSBT_IN_SCRIPTSIG:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input final scriptSig already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Final scriptSig key is more than one byte type");
                    }
                    s >> final_script_sig;
                    break;
                }
                case PSBT_IN_SCRIPTWITNESS:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input final scriptWitness already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Final scriptWitness key is more than one byte type");
                    }
                    UnserializeFromVector(s, final_script_witness.stack);
                    break;
                }
                case PSBT_IN_RIPEMD160:
                {
                    // Make sure that the key is the size of a ripemd160 hash + 1
                    if (key.size() != CRIPEMD160::OUTPUT_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type ripemd160 preimage");
                    }
                    // Read in the hash from key
                    std::vector<unsigned char> hash_vec(key.begin() + 1, key.end());
                    uint160 hash(hash_vec);
                    if (ripemd160_preimages.count(hash) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input ripemd160 preimage already provided");
                    }

                    // Read in the preimage from value
                    std::vector<unsigned char> preimage;
                    s >> preimage;

                    // Add to preimages list
                    ripemd160_preimages.emplace(hash, std::move(preimage));
                    break;
                }
                case PSBT_IN_SHA256:
                {
                    // Make sure that the key is the size of a sha256 hash + 1
                    if (key.size() != CSHA256::OUTPUT_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type sha256 preimage");
                    }
                    // Read in the hash from key
                    std::vector<unsigned char> hash_vec(key.begin() + 1, key.end());
                    uint256 hash(hash_vec);
                    if (sha256_preimages.count(hash) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input sha256 preimage already provided");
                    }

                    // Read in the preimage from value
                    std::vector<unsigned char> preimage;
                    s >> preimage;

                    // Add to preimages list
                    sha256_preimages.emplace(hash, std::move(preimage));
                    break;
                }
                case PSBT_IN_HASH160:
                {
                    // Make sure that the key is the size of a hash160 hash + 1
                    if (key.size() != CHash160::OUTPUT_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type hash160 preimage");
                    }
                    // Read in the hash from key
                    std::vector<unsigned char> hash_vec(key.begin() + 1, key.end());
                    uint160 hash(hash_vec);
                    if (hash160_preimages.count(hash) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input hash160 preimage already provided");
                    }

                    // Read in the preimage from value
                    std::vector<unsigned char> preimage;
                    s >> preimage;

                    // Add to preimages list
                    hash160_preimages.emplace(hash, std::move(preimage));
                    break;
                }
                case PSBT_IN_HASH256:
                {
                    // Make sure that the key is the size of a hash256 hash + 1
                    if (key.size() != CHash256::OUTPUT_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type hash256 preimage");
                    }
                    // Read in the hash from key
                    std::vector<unsigned char> hash_vec(key.begin() + 1, key.end());
                    uint256 hash(hash_vec);
                    if (hash256_preimages.count(hash) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input hash256 preimage already provided");
                    }

                    // Read in the preimage from value
                    std::vector<unsigned char> preimage;
                    s >> preimage;

                    // Add to preimages list
                    hash256_preimages.emplace(hash, std::move(preimage));
                    break;
                }
                case PSBT_IN_PREVIOUS_TXID:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, previous txid is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Previous txid key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Previous txid is not allowed in PSBTv0");
                    }
                    UnserializeFromVector(s, prev_txid);
                    break;
                }
                case PSBT_IN_OUTPUT_INDEX:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, previous output's index is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Previous output's index is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Previous output's index is not allowed in PSBTv0");
                    }
                    uint32_t v;
                    UnserializeFromVector(s, v);
                    prev_out = v;
                    break;
                }
                case PSBT_IN_SEQUENCE:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, sequence is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Sequence key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Sequence is not allowed in PSBTv0");
                    }
                    uint32_t v;
                    UnserializeFromVector(s, v);
                    sequence = v;
                    break;
                }
                case PSBT_IN_REQUIRED_TIME_LOCKTIME:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, required time based locktime is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Required time based locktime is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Required time based locktime is not allowed in PSBTv0");
                    }
                    uint32_t v;
                    UnserializeFromVector(s, v);
                    if (v < LOCKTIME_THRESHOLD) {
                        throw std::ios_base::failure("Required time based locktime is invalid (less than 500000000)");
                    }
                    time_locktime = v;
                    break;
                }
                case PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, required height based locktime is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Required height based locktime is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Required height based locktime is not allowed in PSBTv0");
                    }
                    uint32_t v;
                    UnserializeFromVector(s, v);
                    if (v >= LOCKTIME_THRESHOLD) {
                        throw std::ios_base::failure("Required time based locktime is invalid (greater than or equal to 500000000)");
                    }
                    height_locktime = v;
                    break;
                }
                case PSBT_IN_TAP_KEY_SIG:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input Taproot key signature already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input Taproot key signature key is more than one byte type");
                    }
                    s >> m_tap_key_sig;
                    if (m_tap_key_sig.size() < 64) {
                        throw std::ios_base::failure("Input Taproot key path signature is shorter than 64 bytes");
                    } else if (m_tap_key_sig.size() > 65) {
                        throw std::ios_base::failure("Input Taproot key path signature is longer than 65 bytes");
                    }
                    break;
                }
                case PSBT_IN_TAP_SCRIPT_SIG:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input Taproot script signature already provided");
                    } else if (key.size() != 65) {
                        throw std::ios_base::failure("Input Taproot script signature key is not 65 bytes");
                    }
                    SpanReader s_key(s.GetType(), s.GetVersion(), Span{key}.subspan(1));
                    XOnlyPubKey xonly;
                    uint256 hash;
                    s_key >> xonly;
                    s_key >> hash;
                    std::vector<unsigned char> sig;
                    s >> sig;
                    if (sig.size() < 64) {
                        throw std::ios_base::failure("Input Taproot script path signature is shorter than 64 bytes");
                    } else if (sig.size() > 65) {
                        throw std::ios_base::failure("Input Taproot script path signature is longer than 65 bytes");
                    }
                    m_tap_script_sigs.emplace(std::make_pair(xonly, hash), sig);
                    break;
                }
                case PSBT_IN_TAP_LEAF_SCRIPT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input Taproot leaf script already provided");
                    } else if (key.size() < 34) {
                        throw std::ios_base::failure("Taproot leaf script key is not at least 34 bytes");
                    } else if ((key.size() - 2) % 32 != 0) {
                        throw std::ios_base::failure("Input Taproot leaf script key's control block size is not valid");
                    }
                    std::vector<unsigned char> script_v;
                    s >> script_v;
                    if (script_v.empty()) {
                        throw std::ios_base::failure("Input Taproot leaf script must be at least 1 byte");
                    }
                    uint8_t leaf_ver = script_v.back();
                    script_v.pop_back();
                    const auto leaf_script = std::make_pair(CScript(script_v.begin(), script_v.end()), (int)leaf_ver);
                    m_tap_scripts[leaf_script].insert(std::vector<unsigned char>(key.begin() + 1, key.end()));
                    break;
                }
                case PSBT_IN_TAP_BIP32_DERIVATION:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input Taproot BIP32 keypath already provided");
                    } else if (key.size() != 33) {
                        throw std::ios_base::failure("Input Taproot BIP32 keypath key is not at 33 bytes");
                    }
                    SpanReader s_key(s.GetType(), s.GetVersion(), Span{key}.subspan(1));
                    XOnlyPubKey xonly;
                    s_key >> xonly;
                    std::set<uint256> leaf_hashes;
                    uint64_t value_len = ReadCompactSize(s);
                    size_t before_hashes = s.size();
                    s >> leaf_hashes;
                    size_t after_hashes = s.size();
                    size_t hashes_len = before_hashes - after_hashes;
                    if (hashes_len > value_len) {
                        throw std::ios_base::failure("Input Taproot BIP32 keypath has an invalid length");
                    }
                    size_t origin_len = value_len - hashes_len;
                    m_tap_bip32_paths.emplace(xonly, std::make_pair(leaf_hashes, DeserializeKeyOrigin(s, origin_len)));
                    break;
                }
                case PSBT_IN_TAP_INTERNAL_KEY:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input Taproot internal key already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input Taproot internal key key is more than one byte type");
                    }
                    UnserializeFromVector(s, m_tap_internal_key);
                    break;
                }
                case PSBT_IN_TAP_MERKLE_ROOT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, input Taproot merkle root already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Input Taproot merkle root key is more than one byte type");
                    }
                    UnserializeFromVector(s, m_tap_merkle_root);
                    break;
                }
                case PSBT_IN_MWEB_OUTPUT_ID:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB output ID is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB output ID is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB output ID is not allowed in PSBTv0");
                    }

                    mw::Hash v;
                    UnserializeFromVector(s, v);
                    mweb_output_id = v;
                    break;
                }
                case PSBT_IN_MWEB_COMMIT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB commitment is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB commitment is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB commitment is not allowed in PSBTv0");
                    }

                    Commitment v;
                    UnserializeFromVector(s, v);
                    mweb_output_commit = v;
                    break;
                }
                case PSBT_IN_MWEB_OUTPUT_PUBKEY:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB output public key is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB output public key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB output public key is not allowed in PSBTv0");
                    }

                    PublicKey v;
                    UnserializeFromVector(s, v);
                    mweb_output_pubkey = v;
                    break;
                }
                case PSBT_IN_MWEB_INPUT_PUBKEY:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB input public key is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB input public key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB input public key is not allowed in PSBTv0");
                    }

                    PublicKey v;
                    UnserializeFromVector(s, v);
                    mweb_input_pubkey = v;
                    break;
                }
                case PSBT_IN_MWEB_FEATURES:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB features is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB features key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB features is not allowed in PSBTv0");
                    }

                    uint8_t features;
                    UnserializeFromVector(s, features);
                    mweb_features = features;
                    break;
                }
                case PSBT_IN_MWEB_EXTRA_DATA:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB extra data is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB extra data is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB extra data is not allowed in PSBTv0");
                    }
                    s >> mweb_extra_data;
                    break;
                }
                case PSBT_IN_MWEB_INPUT_SIG:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB signature is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB signature is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB signature is not allowed in PSBTv0");
                    }

                    Signature v;
                    UnserializeFromVector(s, v);
                    mweb_sig = v;
                    break;
                }
                case PSBT_IN_MWEB_ADDR_DESCRIPTOR:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB address descriptor is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB address descriptor is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB address descriptor is not allowed in PSBTv0");
                    }

                    std::vector<unsigned char> v;
                    s >> v;

                    // Backward compatibility for pre-descriptor PSBTs that used
                    // key 0x96 as a 4-byte MWEB address index.
                    if (v.size() == sizeof(uint32_t)) {
                        break;
                    }

                    bool is_ascii = true;
                    for (const unsigned char c : v) {
                        if (c < 0x20 || c > 0x7e) {
                            is_ascii = false;
                            break;
                        }
                    }

                    std::string descriptor(v.begin(), v.end());
                    if (!is_ascii || descriptor.rfind("mweb(", 0) != 0) {
                        throw std::ios_base::failure("MWEB address descriptor must be an ASCII mweb() descriptor");
                    }

                    mweb_address_descriptor = std::move(descriptor);
                    break;
                }
                case PSBT_IN_MWEB_AMOUNT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB amount is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB amount is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB amount is not allowed in PSBTv0");
                    }

                    CAmount v;
                    UnserializeFromVector(s, v);
                    mweb_amount = v;
                    break;
                }
                case PSBT_IN_MWEB_SHARED_SECRET:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB shared secret is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB shared secret is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB shared secret is not allowed in PSBTv0");
                    }

                    SecretKey v;
                    UnserializeFromVector(s, v);
                    mweb_shared_secret = v;
                    break;
                }
                case PSBT_IN_MWEB_KEY_EXCHANGE_PK:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB key exchange public key is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB key exchange public key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB key exchange public key is not allowed in PSBTv0");
                    }

                    PublicKey v;
                    UnserializeFromVector(s, v);
                    mweb_key_exchange_pubkey = v;
                    break;
                }
                case PSBT_IN_PROPRIETARY:
                {
                    PSBTProprietary this_prop;
                    skey >> this_prop.identifier;
                    this_prop.subtype = ReadCompactSize(skey);
                    this_prop.key = key;

                    if (m_proprietary.count(this_prop) > 0) {
                        throw std::ios_base::failure("Duplicate Key, proprietary key already found");
                    }
                    s >> this_prop.value;
                    m_proprietary.insert(this_prop);
                    break;
                }
                // Unknown stuff
                default:
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
            }
        }

        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of an input map");
        }

        // Make sure required PSBTv2 fields are present
        if (m_psbt_version >= 2 && !IsMWEB()) {
            if (prev_txid.IsNull()) {
                throw std::ios_base::failure("Previous TXID is required in PSBTv2");
            }
            if (prev_out == std::nullopt) {
                throw std::ios_base::failure("Previous output's index is required in PSBTv2");
            }
        }
    }

    template <typename Stream>
    PSBTInput(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A structure for PSBTs which contains per output information */
struct PSBTOutput
{
    CScript redeem_script;
    CScript witness_script;
    std::map<CPubKey, KeyOriginInfo> hd_keypaths;
    XOnlyPubKey m_tap_internal_key;
    std::vector<std::tuple<uint8_t, uint8_t, CScript>> m_tap_tree;
    std::map<XOnlyPubKey, std::pair<std::set<uint256>, KeyOriginInfo>> m_tap_bip32_paths;

    std::optional<CAmount> amount;
    std::optional<CScript> script;

    // MWEB Fields
    std::optional<StealthAddress> mweb_stealth_address;
    std::optional<Commitment> mweb_commit;
    std::optional<uint8_t> mweb_features;
    std::optional<PublicKey> mweb_sender_pubkey;
    std::optional<PublicKey> mweb_output_pubkey;
    std::vector<uint8_t> mweb_extra_data;
    std::optional<mw::OutputStandardFields> mweb_standard_fields;
    std::optional<RangeProof::CPtr> mweb_rangeproof;
    std::optional<Signature> mweb_sig;

    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;
    std::set<PSBTProprietary> m_proprietary;

    uint32_t m_psbt_version;

    bool IsNull() const;
    bool IsMWEB() const noexcept { return mweb_stealth_address.has_value() || mweb_commit.has_value(); }
    void FillSignatureData(SignatureData& sigdata) const;
    void FromSignatureData(const SignatureData& sigdata);
    void Merge(const PSBTOutput& output);
    PSBTOutput(uint32_t version) : m_psbt_version(version) {}

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        // Write the redeem script
        if (!redeem_script.empty()) {
            SerializeToVector(s, CompactSizeWriter(PSBT_OUT_REDEEMSCRIPT));
            s << redeem_script;
        }

        // Write the witness script
        if (!witness_script.empty()) {
            SerializeToVector(s, CompactSizeWriter(PSBT_OUT_WITNESSSCRIPT));
            s << witness_script;
        }

        // Write any hd keypaths
        SerializeHDKeypaths(s, hd_keypaths, CompactSizeWriter(PSBT_OUT_BIP32_DERIVATION));

        if (m_psbt_version >= 2) {
            // Write amount and spk
            if (amount != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_AMOUNT));
                SerializeToVector(s, *amount);
            }
            if (script.has_value()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_SCRIPT));
                s << *script;
            }
        }

        // Write proprietary things
        for (const auto& entry : m_proprietary) {
            s << entry.key;
            s << entry.value;
        }

        // Write taproot internal key
        if (!m_tap_internal_key.IsNull()) {
            SerializeToVector(s, PSBT_OUT_TAP_INTERNAL_KEY);
            s << ToByteVector(m_tap_internal_key);
        }

        // Write taproot tree
        if (!m_tap_tree.empty()) {
            SerializeToVector(s, PSBT_OUT_TAP_TREE);
            std::vector<unsigned char> value;
            CVectorWriter s_value(s.GetType(), s.GetVersion(), value, 0);
            for (const auto& [depth, leaf_ver, script] : m_tap_tree) {
                s_value << depth;
                s_value << leaf_ver;
                s_value << script;
            }
            s << value;
        }

        // Write taproot bip32 keypaths
        for (const auto& [xonly, leaf] : m_tap_bip32_paths) {
            const auto& [leaf_hashes, origin] = leaf;
            SerializeToVector(s, PSBT_OUT_TAP_BIP32_DERIVATION, xonly);
            std::vector<unsigned char> value;
            CVectorWriter s_value(s.GetType(), s.GetVersion(), value, 0);
            s_value << leaf_hashes;
            SerializeKeyOrigin(s_value, origin);
            s << value;
        }

        // MWEB fields
        if (m_psbt_version >= 2) {
            if (mweb_stealth_address != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_STEALTH_ADDRESS));
                SerializeToVector(s, *mweb_stealth_address);
            }
            if (mweb_commit != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_COMMIT));
                SerializeToVector(s, *mweb_commit);
            }
            if (mweb_features != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_FEATURES));
                SerializeToVector(s, *mweb_features);
            }
            if (mweb_sender_pubkey != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_SENDER_PUBKEY));
                SerializeToVector(s, *mweb_sender_pubkey);
            }
            if (mweb_output_pubkey != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_OUTPUT_PUBKEY));
                SerializeToVector(s, *mweb_output_pubkey);
            }
            if (!mweb_extra_data.empty()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_EXTRA_DATA));
                s << mweb_extra_data;
            }
            if (mweb_standard_fields != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_STANDARD_FIELDS));
                SerializeToVector(s, *mweb_standard_fields);
            }
            if (mweb_rangeproof != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_RANGEPROOF));
                SerializeToVector(s, *mweb_rangeproof.value());
            }
            if (mweb_sig != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_OUT_MWEB_SIG));
                SerializeToVector(s, *mweb_sig);
            }
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Used for duplicate key detection
        std::set<std::vector<unsigned char>> key_lookup;

        // Read loop
        bool found_sep = false;
        while(!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // Type is compact size uint at beginning of key
            SpanReader skey(s.GetType(), s.GetVersion(), key);
            uint64_t type = ReadCompactSize(skey);

            // Do stuff based on type
            switch(type) {
                case PSBT_OUT_REDEEMSCRIPT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output redeemScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output redeemScript key is more than one byte type");
                    }
                    s >> redeem_script;
                    break;
                }
                case PSBT_OUT_WITNESSSCRIPT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output witnessScript already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output witnessScript key is more than one byte type");
                    }
                    s >> witness_script;
                    break;
                }
                case PSBT_OUT_BIP32_DERIVATION:
                {
                    DeserializeHDKeypaths(s, key, hd_keypaths);
                    break;
                }
                case PSBT_OUT_AMOUNT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output amount is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output amount key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Output amount is not allowed in PSBTv0");
                    }
                    CAmount v;
                    UnserializeFromVector(s, v);
                    amount = v;
                    break;
                }
                case PSBT_OUT_SCRIPT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output script is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output script key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("Output script is not allowed in PSBTv0");
                    }
                    CScript v;
                    s >> v;
                    script = v;
                    break;
                }
                case PSBT_OUT_TAP_INTERNAL_KEY:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output Taproot internal key already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output Taproot internal key key is more than one byte type");
                    }
                    UnserializeFromVector(s, m_tap_internal_key);
                    break;
                }
                case PSBT_OUT_TAP_TREE:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output Taproot tree already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Output Taproot tree key is more than one byte type");
                    }
                    std::vector<unsigned char> tree_v;
                    s >> tree_v;
                    SpanReader s_tree(s.GetType(), s.GetVersion(), tree_v);
                    if (s_tree.empty()) {
                        throw std::ios_base::failure("Output Taproot tree must not be empty");
                    }
                    TaprootBuilder builder;
                    while (!s_tree.empty()) {
                        uint8_t depth;
                        uint8_t leaf_ver;
                        CScript script;
                        s_tree >> depth;
                        s_tree >> leaf_ver;
                        s_tree >> script;
                        if (depth > TAPROOT_CONTROL_MAX_NODE_COUNT) {
                            throw std::ios_base::failure("Output Taproot tree has as leaf greater than Taproot maximum depth");
                        }
                        if ((leaf_ver & ~TAPROOT_LEAF_MASK) != 0) {
                            throw std::ios_base::failure("Output Taproot tree has a leaf with an invalid leaf version");
                        }
                        m_tap_tree.emplace_back(depth, leaf_ver, script);
                        builder.Add((int)depth, script, (int)leaf_ver, true /* track */);
                    }
                    if (!builder.IsComplete()) {
                        throw std::ios_base::failure("Output Taproot tree is malformed");
                    }
                    break;
                }
                case PSBT_OUT_TAP_BIP32_DERIVATION:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, output Taproot BIP32 keypath already provided");
                    } else if (key.size() != 33) {
                        throw std::ios_base::failure("Output Taproot BIP32 keypath key is not at 33 bytes");
                    }
                    XOnlyPubKey xonly(uint256({key.begin() + 1, key.begin() + 33}));
                    std::set<uint256> leaf_hashes;
                    uint64_t value_len = ReadCompactSize(s);
                    size_t before_hashes = s.size();
                    s >> leaf_hashes;
                    size_t after_hashes = s.size();
                    size_t hashes_len = before_hashes - after_hashes;
                    if (hashes_len > value_len) {
                        throw std::ios_base::failure("Output Taproot BIP32 keypath has an invalid length");
                    }
                    size_t origin_len = value_len - hashes_len;
                    m_tap_bip32_paths.emplace(xonly, std::make_pair(leaf_hashes, DeserializeKeyOrigin(s, origin_len)));
                    break;
                }
                // MWEB fields
                case PSBT_OUT_MWEB_STEALTH_ADDRESS: {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB stealth address is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB stealth address is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB stealth address is not allowed in PSBTv0");
                    }
                    StealthAddress v;
                    UnserializeFromVector(s, v);
                    mweb_stealth_address = v;
                    break;
                }
                case PSBT_OUT_MWEB_COMMIT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB commitment is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB commitment is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB commitment is not allowed in PSBTv0");
                    }
                    Commitment v;
                    UnserializeFromVector(s, v);
                    mweb_commit = v;
                    break;
                }
                case PSBT_OUT_MWEB_FEATURES:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB features is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB features key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB features is not allowed in PSBTv0");
                    }

                    uint8_t features;
                    UnserializeFromVector(s, features);
                    mweb_features = features;
                    break;
                }
                case PSBT_OUT_MWEB_SENDER_PUBKEY:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB sender pubkey is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB sender pubkey is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB sender pubkey is not allowed in PSBTv0");
                    }
                    PublicKey v;
                    UnserializeFromVector(s, v);
                    mweb_sender_pubkey = v;
                    break;
                }
                case PSBT_OUT_MWEB_OUTPUT_PUBKEY:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB output pubkey is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB output pubkey is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB output pubkey is not allowed in PSBTv0");
                    }
                    PublicKey v;
                    UnserializeFromVector(s, v);
                    mweb_output_pubkey = v;
                    break;
                }
                case PSBT_OUT_MWEB_EXTRA_DATA:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB extra data is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB extra data is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB extra data is not allowed in PSBTv0");
                    }
                    s >> mweb_extra_data;
                    break;
                }
                case PSBT_OUT_MWEB_STANDARD_FIELDS:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB standard fields are already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB standard fields key is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB standard fields are not allowed in PSBTv0");
                    }
                    mw::OutputStandardFields v;
                    UnserializeFromVector(s, v);
                    mweb_standard_fields = v;
                    break;
                }
                case PSBT_OUT_MWEB_RANGEPROOF:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB rangeproof is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB rangeproof is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB rangeproof is not allowed in PSBTv0");
                    }
                    RangeProof v;
                    UnserializeFromVector(s, v);
                    mweb_rangeproof = std::make_shared<RangeProof>(std::move(v));
                    break;
                }
                case PSBT_OUT_MWEB_SIG:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, MWEB signature is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("MWEB signature is more than one byte type");
                    } else if (m_psbt_version == 0) {
                        throw std::ios_base::failure("MWEB signature is not allowed in PSBTv0");
                    }
                    Signature v;
                    UnserializeFromVector(s, v);
                    mweb_sig = v;
                    break;
                }
                case PSBT_OUT_PROPRIETARY:
                {
                    PSBTProprietary this_prop;
                    skey >> this_prop.identifier;
                    this_prop.subtype = ReadCompactSize(skey);
                    this_prop.key = key;

                    if (m_proprietary.count(this_prop) > 0) {
                        throw std::ios_base::failure("Duplicate Key, proprietary key already found");
                    }
                    s >> this_prop.value;
                    m_proprietary.insert(this_prop);
                    break;
                }
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
                }
            }
        }

        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of an output map");
        }

        // Make sure required PSBTv2 fields are present
        if (m_psbt_version >= 2) {
            if (amount == std::nullopt) {
                    throw std::ios_base::failure("Output amount is required in PSBTv2");
            }
            if (!script.has_value() && !mweb_stealth_address.has_value() && !mweb_commit.has_value()) {
                    throw std::ios_base::failure("Output script is required in PSBTv2");
            }
        }
    }

    template <typename Stream>
    PSBTOutput(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A structure for PSBTs which contains per MWEB kernel information */
struct PSBTKernel
{
    std::optional<uint8_t> features;
    std::optional<Commitment> commit;
    std::optional<PublicKey> stealth_commit;
    std::optional<CAmount> fee;
    std::optional<CAmount> pegin_amount;
    std::vector<PegOutCoin> pegouts;
    std::optional<int32_t> lock_height;
    std::vector<uint8_t> extra_data;
    std::optional<Signature> sig;

    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;

    PSBTKernel() = default;

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        if (features != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_FEATURES));
            SerializeToVector(s, *features);
        }
        if (commit != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_EXCESS_COMMIT));
            SerializeToVector(s, *commit);
        }
        if (stealth_commit != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_STEALTH_COMMIT));
            SerializeToVector(s, *stealth_commit);
        }
        if (fee != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_FEE));
            SerializeToVector(s, *fee);
        }
        if (pegin_amount != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_PEGIN_AMOUNT));
            SerializeToVector(s, *pegin_amount);
        }
        for (size_t i = 0; i < pegouts.size(); i++) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_PEGOUT), CompactSizeWriter(i));
            SerializeToVector(s, pegouts[i].GetAmount(), pegouts[i].GetScriptPubKey());
        }
        if (lock_height != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_LOCK_HEIGHT));
            SerializeToVector(s, *lock_height);
        }
        if (!extra_data.empty()) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_EXTRA_DATA));
            s << extra_data;
        }
        if (sig != std::nullopt) {
            SerializeToVector(s, CompactSizeWriter(PSBT_KERN_SIG));
            SerializeToVector(s, *sig);
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Used for duplicate key detection
        std::set<std::vector<unsigned char>> key_lookup;
        std::map<uint64_t, PegOutCoin> indexed_pegouts;

        // Read loop
        bool found_sep = false;
        while (!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_KERN_FEATURES:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel features is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel features key is more than one byte type");
                    }

                    uint8_t v;
                    UnserializeFromVector(s, v);
                    features = v;
                    break;
                }
                case PSBT_KERN_EXCESS_COMMIT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel commitment is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel commitment is more than one byte type");
                    }
                    Commitment v;
                    UnserializeFromVector(s, v);
                    commit = v;
                    break;
                }
                case PSBT_KERN_STEALTH_COMMIT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel stealth commitment is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel stealth commitment is more than one byte type");
                    }
                    PublicKey v;
                    UnserializeFromVector(s, v);
                    stealth_commit = v;
                    break;
                }
                case PSBT_KERN_FEE:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel fee is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel fee is more than one byte type");
                    }
                    CAmount v;
                    UnserializeFromVector(s, v);
                    fee = v;
                    break;
                }
                case PSBT_KERN_PEGIN_AMOUNT: {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel pegin is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel pegin is more than one byte type");
                    }
                    CAmount v;
                    UnserializeFromVector(s, v);
                    pegin_amount = v;
                    break;
                }
                case PSBT_KERN_PEGOUT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, pegout is already provided");
                    } else if (key.size() == 1) {
                        throw std::ios_base::failure("Kernel pegout key is missing index");
                    }

                    SpanReader s_key(s.GetType(), s.GetVersion(), Span{key}.subspan(1));
                    const uint64_t index = ReadCompactSize(s_key);
                    if (!s_key.empty()) {
                        throw std::ios_base::failure("Kernel pegout key has unexpected data after index");
                    }

                    CAmount amount;
                    CScript script;
                    UnserializeFromVector(s, amount, script);
                    // Mirror PegOutCoin's own deserialization check: a PSBT
                    // carrying an empty pegout script could never become a
                    // relayable transaction (peers reject it at parse time).
                    if (script.empty()) {
                        throw std::ios_base::failure("Pegout scriptPubKey must not be empty");
                    }
                    if (!indexed_pegouts.emplace(index, PegOutCoin(amount, std::move(script))).second) {
                        throw std::ios_base::failure("Duplicate Key, pegout index is already provided");
                    }
                    break;
                }
                case PSBT_KERN_LOCK_HEIGHT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel lock height is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel lock height is more than one byte type");
                    }
                    int32_t v;
                    UnserializeFromVector(s, v);
                    lock_height = v;
                    break;
                }
                case PSBT_KERN_EXTRA_DATA:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel extra data is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel extra data is more than one byte type");
                    }
                    s >> extra_data;
                    break;
                }
                case PSBT_KERN_SIG:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, kernel signature is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Kernel signature is more than one byte type");
                    }
                    Signature v;
                    UnserializeFromVector(s, v);
                    sig = v;
                    break;
                }
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
                }
            }
        }


        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of a kernel map");
        }

        uint64_t expected_index = 0;
        for (auto& [index, pegout] : indexed_pegouts) {
            if (index != expected_index) {
                throw std::ios_base::failure("Kernel pegout indexes must be contiguous");
            }
            pegouts.push_back(std::move(pegout));
            ++expected_index;
        }
    }

    template <typename Stream>
    PSBTKernel(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A version of CTransaction with the PSBT format*/
struct PartiallySignedTransaction
{
    std::optional<CMutableTransaction> tx{std::nullopt};
    uint32_t m_psbt_version{0};

    // We use a vector of CExtPubKey in the event that there happens to be the same KeyOriginInfos for different CExtPubKeys
    // Note that this map swaps the key and values from the serialization
    std::map<KeyOriginInfo, std::set<CExtPubKey>> m_xpubs{};
    int32_t tx_version{0};
    std::optional<uint32_t> fallback_locktime{std::nullopt};
    std::optional<std::bitset<8>> m_tx_modifiable{std::nullopt};
    std::optional<BlindingFactor> mweb_tx_offset{std::nullopt};
    std::optional<BlindingFactor> mweb_stealth_offset{std::nullopt};
    std::vector<PSBTInput> inputs{};
    std::vector<PSBTOutput> outputs{};
    std::vector<PSBTKernel> kernels{};
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown{};
    std::set<PSBTProprietary> m_proprietary;

    bool IsNull() const;
    uint32_t GetPSBTVersion() const;
    bool ContainsMWEBComponents() const noexcept;

    /** Merge psbt into this. The two psbts must have the same underlying CTransaction (i.e. the
      * same actual Bitcoin transaction.) Returns true if the merge succeeded, false otherwise. */
    [[nodiscard]] bool Merge(const PartiallySignedTransaction& psbt);
    bool AddInput(PSBTInput& psbtin);
    bool AddOutput(const PSBTOutput& psbtout);
    void SetupFromTx(const CMutableTransaction& tx);
    bool ComputeTimeLock(uint32_t& locktime) const;
    CMutableTransaction GetUnsignedTx() const;
    uint256 GetUniqueID() const;
    PartiallySignedTransaction() = default;
    explicit PartiallySignedTransaction(const CMutableTransaction& tx, uint32_t version = 2);

    bool IsComplete() const noexcept;

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        if (GetPSBTVersion() == 0 && ContainsMWEBComponents()) {
            throw std::ios_base::failure("MWEB fields are not allowed in PSBTv0");
        }

        // magic bytes
        s << PSBT_MAGIC_BYTES;

        if (GetPSBTVersion() == 0) {
            // unsigned tx flag
            SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_UNSIGNED_TX));

            // Write serialized tx to a stream
            OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB);
            SerializeToVector(os, GetUnsignedTx());
        }

        // Write xpubs
        for (const auto& xpub_pair : m_xpubs) {
            for (const auto& xpub : xpub_pair.second) {
                unsigned char ser_xpub[BIP32_EXTKEY_WITH_VERSION_SIZE];
                xpub.EncodeWithVersion(ser_xpub);
                // Note that the serialization swaps the key and value
                // The xpub is the key (for uniqueness) while the path is the value
                SerializeToVector(s, PSBT_GLOBAL_XPUB, ser_xpub);
                SerializeHDKeypath(s, xpub_pair.first);
            }
        }

        if (GetPSBTVersion() >= 2) {
            // Write PSBTv2 tx version, locktime, counts, etc.
            SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_TX_VERSION));
            SerializeToVector(s, tx_version);
            if (fallback_locktime != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_FALLBACK_LOCKTIME));
                SerializeToVector(s, *fallback_locktime);
            }

            SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_INPUT_COUNT));
            SerializeToVector(s, CompactSizeWriter(inputs.size()));
            SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_OUTPUT_COUNT));
            SerializeToVector(s, CompactSizeWriter(outputs.size()));

            if (m_tx_modifiable != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_TX_MODIFIABLE));
                SerializeToVector(s, static_cast<uint8_t>(m_tx_modifiable->to_ulong()));
            }

            // MWEB fields
            if (!kernels.empty()) {
                SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_MWEB_KERNEL_COUNT));
                SerializeToVector(s, CompactSizeWriter(kernels.size()));
            }
            if (mweb_tx_offset != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_MWEB_TX_OFFSET));
                SerializeToVector(s, *mweb_tx_offset);
            }
            if (mweb_stealth_offset != std::nullopt) {
                SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET));
                SerializeToVector(s, *mweb_stealth_offset);
            }
        }

        // PSBT version
        if (GetPSBTVersion() > 0) {
            SerializeToVector(s, CompactSizeWriter(PSBT_GLOBAL_VERSION));
            SerializeToVector(s, m_psbt_version);
        }

        // Write proprietary things
        for (const auto& entry : m_proprietary) {
            s << entry.key;
            s << entry.value;
        }

        // Write the unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        // Separator
        s << PSBT_SEPARATOR;

        // Write inputs
        for (const PSBTInput& input : inputs) {
            s << input;
        }
        // Write outputs
        for (const PSBTOutput& output : outputs) {
            s << output;
        }
        // Write kernels
        for (const PSBTKernel& kernel : kernels) {
            s << kernel;
        }
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read the magic bytes
        uint8_t magic[5];
        s >> magic;
        if (!std::equal(magic, magic + 5, PSBT_MAGIC_BYTES)) {
            throw std::ios_base::failure("Invalid PSBT magic bytes");
        }

        // Used for duplicate key detection
        std::set<std::vector<unsigned char>> key_lookup;

        // Track the global xpubs we have already seen. Just for sanity checking
        std::set<CExtPubKey> global_xpubs;

        // Read global data
        bool found_sep = false;
        bool found_tx_version = false;
        uint64_t input_count = 0;
        uint64_t output_count = 0;
        uint64_t kernel_count = 0;
        bool found_input_count = false;
        bool found_output_count = false;
        bool found_kernel_count = false;
        while(!s.empty()) {
            // Read
            std::vector<unsigned char> key;
            s >> key;

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.empty()) {
                found_sep = true;
                break;
            }

            // Type is compact size uint at beginning of key
            SpanReader skey(s.GetType(), s.GetVersion(), key);
            uint64_t type = ReadCompactSize(skey);

            // Do stuff based on type
            switch(type) {
                case PSBT_GLOBAL_UNSIGNED_TX:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, unsigned tx already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global unsigned tx key is more than one byte type");
                    }
                    CMutableTransaction mtx;
                    // Set the stream to unserialize without witness or MWEB since this should always be non-witness v0 data
                    OverrideStream<Stream> os(&s, s.GetType(), s.GetVersion() | SERIALIZE_TRANSACTION_NO_WITNESS | SERIALIZE_NO_MWEB);
                    UnserializeFromVector(os, mtx);
                    tx = std::move(mtx);
                    // Make sure that all scriptSigs and scriptWitnesses are empty
                    for (const CTxIn& txin : tx->vin) {
                        if (!txin.scriptSig.empty() || !txin.scriptWitness.IsNull()) {
                            throw std::ios_base::failure("Unsigned tx does not have empty scriptSigs and scriptWitnesses.");
                        }
                    }
                    // Set the input and output counts
                    input_count = tx->vin.size();
                    output_count = tx->vout.size();
                    break;
                }
                case PSBT_GLOBAL_TX_VERSION:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global transaction version is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global transaction version key is more than one byte type");
                    }
                    UnserializeFromVector(s, tx_version);
                    found_tx_version = true;
                    break;
                }
                case PSBT_GLOBAL_FALLBACK_LOCKTIME:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global fallback locktime is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global fallback locktime key is more than one byte type");
                    }
                    uint32_t v;
                    UnserializeFromVector(s, v);
                    fallback_locktime = v;
                    break;
                }
                case PSBT_GLOBAL_INPUT_COUNT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global input count is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global input count key is more than one byte type");
                    }
                    CompactSizeReader reader(input_count);
                    UnserializeFromVector(s, reader);
                    found_input_count = true;
                    break;
                }
                case PSBT_GLOBAL_OUTPUT_COUNT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global output count is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global output count key is more than one byte type");
                    }
                    CompactSizeReader reader(output_count);
                    UnserializeFromVector(s, reader);
                    found_output_count = true;
                    break;
                }
                case PSBT_GLOBAL_MWEB_KERNEL_COUNT:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global kernel count is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global kernel count key is more than one byte type");
                    }
                    CompactSizeReader reader(kernel_count);
                    UnserializeFromVector(s, reader);
                    found_kernel_count = true;
                    break;
                }
                case PSBT_GLOBAL_MWEB_TX_OFFSET:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global MWEB tx offset is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global MWEB tx offset key is more than one byte type");
                    }
                    BlindingFactor v;
                    UnserializeFromVector(s, v);
                    mweb_tx_offset = v;
                    break;
                }
                case PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, global MWEB stealth offset is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global MWEB stealth offset key is more than one byte type");
                    }
                    BlindingFactor v;
                    UnserializeFromVector(s, v);
                    mweb_stealth_offset = v;
                    break;
                }
                case PSBT_GLOBAL_TX_MODIFIABLE:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, tx modifiable flags is already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global tx modifiable flags key is more than one byte type");
                    }
                    uint8_t tx_mod;
                    UnserializeFromVector(s, tx_mod);
                    m_tx_modifiable.emplace(tx_mod);
                    break;
                }
                case PSBT_GLOBAL_XPUB:
                {
                    if (key.size() != BIP32_EXTKEY_WITH_VERSION_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type global xpub");
                    }
                    // Read in the xpub from key
                    CExtPubKey xpub;
                    xpub.DecodeWithVersion(&key.data()[1]);
                    if (!xpub.pubkey.IsFullyValid()) {
                       throw std::ios_base::failure("Invalid pubkey");
                    }
                    if (global_xpubs.count(xpub) > 0) {
                       throw std::ios_base::failure("Duplicate key, global xpub already provided");
                    }
                    global_xpubs.insert(xpub);
                    // Read in the keypath from stream
                    KeyOriginInfo keypath;
                    DeserializeHDKeypath(s, keypath);

                    // Note that we store these swapped to make searches faster.
                    // Serialization uses xpub -> keypath to enqure key uniqueness
                    if (m_xpubs.count(keypath) == 0) {
                        // Make a new set to put the xpub in
                        m_xpubs[keypath] = {xpub};
                    } else {
                        // Insert xpub into existing set
                        m_xpubs[keypath].insert(xpub);
                    }
                    break;
                }
                case PSBT_GLOBAL_VERSION:
                {
                    if (!key_lookup.emplace(key).second) {
                        throw std::ios_base::failure("Duplicate Key, version already provided");
                    } else if (key.size() != 1) {
                        throw std::ios_base::failure("Global version key is more than one byte type");
                    }
                    UnserializeFromVector(s, m_psbt_version);
                    if (m_psbt_version > PSBT_HIGHEST_VERSION) {
                        throw std::ios_base::failure("Unsupported version number");
                    }
                    break;
                }
                case PSBT_GLOBAL_PROPRIETARY:
                {
                    PSBTProprietary this_prop;
                    skey >> this_prop.identifier;
                    this_prop.subtype = ReadCompactSize(skey);
                    this_prop.key = key;

                    if (m_proprietary.count(this_prop) > 0) {
                        throw std::ios_base::failure("Duplicate Key, proprietary key already found");
                    }
                    s >> this_prop.value;
                    m_proprietary.insert(this_prop);
                    break;
                }
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    std::vector<unsigned char> val_bytes;
                    s >> val_bytes;
                    unknown.emplace(std::move(key), std::move(val_bytes));
                }
            }
        }

        if (!found_sep) {
            throw std::ios_base::failure("Separator is missing at the end of the global map");
        }

        const uint32_t psbt_ver = GetPSBTVersion();

        // Check PSBT version constraints
        if (psbt_ver == 0) {
            // Make sure that we got an unsigned tx for PSBTv0
            if (!tx) {
                throw std::ios_base::failure("No unsigned transaction was provided");
            }
            // Make sure no PSBTv2 fields are present
            if (found_tx_version) {
                throw std::ios_base::failure("PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0");
            }
            if (fallback_locktime != std::nullopt) {
                throw std::ios_base::failure("PSBT_GLOBAL_FALLBACK_LOCKTIME is not allowed in PSBTv0");
            }
            if (found_input_count) {
                throw std::ios_base::failure("PSBT_GLOBAL_INPUT_COUNT is not allowed in PSBTv0");
            }
            if (found_output_count) {
                throw std::ios_base::failure("PSBT_GLOBAL_OUTPUT_COUNT is not allowed in PSBTv0");
            }
            if (found_kernel_count) {
                throw std::ios_base::failure("PSBT_GLOBAL_MWEB_KERNEL_COUNT is not allowed in PSBTv0");
            }
            if (mweb_tx_offset != std::nullopt) {
                throw std::ios_base::failure("PSBT_GLOBAL_MWEB_TX_OFFSET is not allowed in PSBTv0");
            }
            if (mweb_stealth_offset != std::nullopt) {
                throw std::ios_base::failure("PSBT_GLOBAL_MWEB_TX_STEALTH_OFFSET is not allowed in PSBTv0");
            }
            if (m_tx_modifiable != std::nullopt) {
                throw std::ios_base::failure("PSBT_GLOBAL_TX_MODIFIABLE is not allowed in PSBTv0");
            }
        }
        // Disallow v1
        if (psbt_ver == 1) {
            throw std::ios_base::failure("There is no PSBT version 1");
        }
        if (psbt_ver >= 2) {
            // Tx version, input, and output counts are required
            if (!found_tx_version) {
                throw std::ios_base::failure("PSBT_GLOBAL_TX_VERSION is required in PSBTv2");
            }
            if (!found_input_count) {
                throw std::ios_base::failure("PSBT_GLOBAL_INPUT_COUNT is required in PSBTv2");
            }
            if (!found_output_count) {
                throw std::ios_base::failure("PSBT_GLOBAL_OUTPUT_COUNT is required in PSBTv2");
            }
            // Unsigned tx is disallowed
            if (tx) {
                throw std::ios_base::failure("PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2");
            }
        }

        // Read input data
        bool mweb_inputs = false;
        unsigned int i = 0;
        while (!s.empty() && i < input_count) {
            PSBTInput input(psbt_ver);
            s >> input;
            if (mweb_inputs && !input.IsMWEB()) {
                throw std::ios_base::failure("MWEB inputs must be last");
            }
            mweb_inputs = input.IsMWEB();
            inputs.push_back(input);

            // Make sure the non-witness utxo matches the outpoint
            if (input.non_witness_utxo && !input.IsMWEB()) {
                if (psbt_ver == 0) {
                    if (input.non_witness_utxo->GetHash() != tx->vin[i].prevout.hash) {
                        throw std::ios_base::failure("Non-witness UTXO does not match outpoint hash");
                    }
                    if (tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size()) {
                        throw std::ios_base::failure("Input specifies output index that does not exist");
                    }
                } else if (psbt_ver >= 2) {
                    if (input.non_witness_utxo->GetHash() != input.prev_txid) {
                        throw std::ios_base::failure("Non-witness UTXO does not match outpoint hash");
                    }
                    if (input.prev_out.value() >= input.non_witness_utxo->vout.size()) {
                        throw std::ios_base::failure("Input specifies output index that does not exist");
                    }
                }
            }
            ++i;
        }
        // Make sure that the number of inputs matches the number of inputs in the transaction
        if (inputs.size() != input_count) {
            throw std::ios_base::failure("Inputs provided does not match the number of inputs in transaction.");
        }

        // Read output data
        bool mweb_outputs = false;
        i = 0;
        while (!s.empty() && i < output_count) {
            PSBTOutput output(psbt_ver);
            s >> output;
            if (mweb_outputs && !output.IsMWEB()) {
                throw std::ios_base::failure("MWEB outputs must be last");
            }
            mweb_outputs = output.IsMWEB();
            outputs.push_back(output);
            ++i;
        }
        // Make sure that the number of outputs matches the number of outputs in the transaction
        if (outputs.size() != output_count) {
            throw std::ios_base::failure("Outputs provided does not match the number of outputs in transaction.");
        }

        // Read kernel data
        i = 0;
        while (!s.empty() && i < kernel_count) {
            PSBTKernel kernel;
            s >> kernel;
            kernels.push_back(kernel);
            ++i;
        }
        // Make sure that the number of kernels matches the number of kernels in the transaction
        if (kernels.size() != kernel_count) {
            throw std::ios_base::failure("Kernels provided does not match the number of kernels in transaction.");
        }
        
        // To make things easier, we split up the global unsigned transaction
        // and use the PSBTv2 fields for PSBTv0.
        if (tx != std::nullopt) {
            SetupFromTx(*tx);
        }
    }

    template <typename Stream>
    PartiallySignedTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

enum class PSBTRole {
    CREATOR,
    UPDATER,
    SIGNER,
    FINALIZER,
    EXTRACTOR
};

std::string PSBTRoleName(PSBTRole role);

/** Compute a PrecomputedTransactionData object from a psbt. */
PrecomputedTransactionData PrecomputePSBTData(const PartiallySignedTransaction& psbt);

/** Checks whether a PSBTInput is already signed by checking for non-null finalized fields. */
bool PSBTInputSigned(const PSBTInput& input);

/** Checks whether a PSBTInput is already signed by doing script verification using final fields. */
bool PSBTInputSignedAndVerified(const PartiallySignedTransaction& psbt, unsigned int input_index, const PrecomputedTransactionData* txdata);

/** Signs a PSBTInput, verifying that all provided data matches what is being signed.
 *
 * txdata should be the output of PrecomputePSBTData (which can be shared across
 * multiple SignPSBTInput calls). If it is nullptr, a dummy signature will be created.
 **/
bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, int sighash = SIGHASH_ALL, SignatureData* out_sigdata = nullptr, bool finalize = true);

/**  Reduces the size of the PSBT by dropping unnecessary `non_witness_utxos` (i.e. complete previous transactions) from a psbt when all inputs are segwit v1. */
void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx, const int& sighash_type);

/** Counts the unsigned inputs of a PSBT. */
size_t CountPSBTUnsignedInputs(const PartiallySignedTransaction& psbt);

/** Updates a PSBTOutput with information from provider.
 *
 * This fills in the redeem_script, witness_script, and hd_keypaths where possible.
 */
void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index);

/**
 * Verifies the positional association between MWEB peg-in outputs and kernels,
 * including known amounts and finalized kernel IDs (defined in psbt_merge.cpp).
 * Partial validation permits placeholder scripts and temporarily unequal
 * counts; final validation requires complete, non-placeholder associations.
 */
[[nodiscard]] bool VerifyPeginOutputs(const PartiallySignedTransaction& psbt, bool require_final);

/**
 * Finalizes a PSBT if possible, combining partial signatures.
 *
 * @param[in,out] psbtx PartiallySignedTransaction to finalize
 * return The finalized CMutableTransaction if the PSBT is now complete. error otherwise
 */
util::Result<CMutableTransaction> FinalizePSBT(PartiallySignedTransaction& psbtx);

/**
 * Combines PSBTs with the same underlying transaction, resulting in a single PSBT with all partial signatures from each input.
 *
 * @param[out] out   the combined PSBT, if successful
 * @param[in]  psbtxs the PSBTs to combine
 * @return error (OK if we successfully combined the transactions, other error if they were not compatible)
 */
[[nodiscard]] TransactionError CombinePSBTs(PartiallySignedTransaction& out, const std::vector<PartiallySignedTransaction>& psbtxs);

//! Decode a base64ed PSBT into a PartiallySignedTransaction
[[nodiscard]] bool DecodeBase64PSBT(PartiallySignedTransaction& decoded_psbt, const std::string& base64_psbt, std::string& error);
//! Decode a raw (binary blob) PSBT into a PartiallySignedTransaction
[[nodiscard]] bool DecodeRawPSBT(PartiallySignedTransaction& decoded_psbt, Span<const std::byte> raw_psbt, std::string& error);

#endif // BITCOIN_PSBT_H
