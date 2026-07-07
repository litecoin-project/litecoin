#ifndef BITCOIN_SCRIPT_PUBKEYPROVIDER_H
#define BITCOIN_SCRIPT_PUBKEYPROVIDER_H

#include <key_io.h>
#include <mw/wallet/Keychain.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/keyorigin.h>
#include <util/bip32.h>
#include <cstdint>
#include <vector>

typedef std::vector<uint32_t> KeyPath;

/** Interface for public key objects in descriptors. */
struct PubkeyProvider
{
protected:
    //! Index of this key expression in the descriptor
    //! E.g. If this PubkeyProvider is key1 in multi(2, key1, key2, key3), then m_expr_index = 0
    uint32_t m_expr_index;

public:
    explicit PubkeyProvider(uint32_t exp_index) : m_expr_index(exp_index) {}

    virtual ~PubkeyProvider() = default;

    /** Compare two public keys represented by this provider.
     * Used by the Miniscript descriptors to check for duplicate keys in the script.
     */
    bool operator<(PubkeyProvider& other) const {
        CPubKey a, b;
        SigningProvider dummy;
        KeyOriginInfo dummy_info;

        GetPubKey(0, dummy, a, dummy_info);
        other.GetPubKey(0, dummy, b, dummy_info);

        return a < b;
    }

    /** Derive a public key.
     *  read_cache is the cache to read keys from (if not nullptr)
     *  write_cache is the cache to write keys to (if not nullptr)
     *  Caches are not exclusive but this is not tested. Currently we use them exclusively
     */
    virtual bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const = 0;

    virtual bool GetKeyOrigin(int pos, KeyOriginInfo& info) const = 0;

    /** Whether this represent multiple public keys at different positions. */
    virtual bool IsRange() const = 0;

    /** Get the size of the generated public key(s) in bytes (33 or 65). */
    virtual size_t GetSize() const = 0;

    /** Get the descriptor string form. */
    virtual std::string ToString() const = 0;

    /** Get the descriptor string form including private data (if available in arg). */
    virtual bool ToPrivateString(const SigningProvider& arg, std::string& out) const = 0;

    /** Get the descriptor string form with the xpub at the last hardened derivation */
    virtual bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache = nullptr) const = 0;

    /** Derive a private key, if private data is available in arg. */
    virtual bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const = 0;
};

class OriginPubkeyProvider final : public PubkeyProvider
{
    KeyOriginInfo m_origin;
    std::unique_ptr<PubkeyProvider> m_provider;

    std::string OriginString() const
    {
        return HexStr(m_origin.fingerprint) + FormatHDKeypath(m_origin.hdkeypath);
    }

public:
    OriginPubkeyProvider(uint32_t exp_index, KeyOriginInfo info, std::unique_ptr<PubkeyProvider> provider) : PubkeyProvider(exp_index), m_origin(std::move(info)), m_provider(std::move(provider)) {}
    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        if (!m_provider->GetPubKey(pos, arg, key, info, read_cache, write_cache)) return false;
        std::copy(std::begin(m_origin.fingerprint), std::end(m_origin.fingerprint), info.fingerprint);
        info.hdkeypath.path.insert(info.hdkeypath.path.begin(), m_origin.hdkeypath.path.begin(), m_origin.hdkeypath.path.end());
        if (m_origin.hdkeypath.mweb_index.has_value()) {
            info.hdkeypath.mweb_index = m_origin.hdkeypath.mweb_index;
        }
        return true;
    }
    bool GetKeyOrigin(int pos, KeyOriginInfo& info) const override
    {
        if (!m_provider->GetKeyOrigin(pos, info)) return false;
        std::copy(std::begin(m_origin.fingerprint), std::end(m_origin.fingerprint), info.fingerprint);
        info.hdkeypath.path.insert(info.hdkeypath.path.begin(), m_origin.hdkeypath.path.begin(), m_origin.hdkeypath.path.end());
        if (m_origin.hdkeypath.mweb_index.has_value()) {
            info.hdkeypath.mweb_index = m_origin.hdkeypath.mweb_index;
        }
        return true;
    }
    bool IsRange() const override { return m_provider->IsRange(); }
    size_t GetSize() const override { return m_provider->GetSize(); }
    std::string ToString() const override { return "[" + OriginString() + "]" + m_provider->ToString(); }
    bool ToPrivateString(const SigningProvider& arg, std::string& ret) const override
    {
        std::string sub;
        if (!m_provider->ToPrivateString(arg, sub)) return false;
        ret = "[" + OriginString() + "]" + std::move(sub);
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& ret, const DescriptorCache* cache) const override
    {
        std::string sub;
        if (!m_provider->ToNormalizedString(arg, sub, cache)) return false;
        // If m_provider is a BIP32PubkeyProvider, we may get a string formatted like a OriginPubkeyProvider
        // In that case, we need to strip out the leading square bracket and fingerprint from the substring,
        // and append that to our own origin string.
        if (sub[0] == '[') {
            sub = sub.substr(9);
            ret = "[" + OriginString() + std::move(sub);
        } else {
            ret = "[" + OriginString() + "]" + std::move(sub);
        }
        return true;
    }
    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        return m_provider->GetPrivKey(pos, arg, key);
    }
};

/** An object representing a parsed constant public key in a descriptor. */
class ConstPubkeyProvider final : public PubkeyProvider
{
    CPubKey m_pubkey;
    bool m_xonly;

public:
    ConstPubkeyProvider(uint32_t exp_index, const CPubKey& pubkey, bool xonly) : PubkeyProvider(exp_index), m_pubkey(pubkey), m_xonly(xonly) {}
    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key, KeyOriginInfo& info, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        key = m_pubkey;
        info.hdkeypath.path.clear();
        CKeyID keyid = m_pubkey.GetID();
        std::copy(keyid.begin(), keyid.begin() + sizeof(info.fingerprint), info.fingerprint);
        return true;
    }
    bool GetKeyOrigin(int pos, KeyOriginInfo& info) const override
    {
        info.hdkeypath.path.clear();
        CKeyID keyid = m_pubkey.GetID();
        std::copy(keyid.begin(), keyid.begin() + sizeof(info.fingerprint), info.fingerprint);
        return true;
    }
    bool IsRange() const override { return false; }
    size_t GetSize() const override { return m_pubkey.size(); }
    std::string ToString() const override { return m_xonly ? HexStr(m_pubkey).substr(2) : HexStr(m_pubkey); }
    bool ToPrivateString(const SigningProvider& arg, std::string& ret) const override
    {
        CKey key;
        if (m_xonly) {
            for (const auto& keyid : XOnlyPubKey(m_pubkey).GetKeyIDs()) {
                arg.GetKey(keyid, key);
                if (key.IsValid()) break;
            }
        } else {
            arg.GetKey(m_pubkey.GetID(), key);
        }
        if (!key.IsValid()) return false;
        ret = EncodeSecret(key);
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& ret, const DescriptorCache* cache) const override
    {
        ret = ToString();
        return true;
    }
    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        return arg.GetKey(m_pubkey.GetID(), key);
    }
};

enum class DeriveType {
    NO,
    UNHARDENED,
    HARDENED,
};

/** An object representing a parsed extended public key in a descriptor. */
class BIP32PubkeyProvider final : public PubkeyProvider
{
    // Root xpub, path, and final derivation step type being used, if any
    CExtPubKey m_root_extkey;
    HDKeyPath m_path;
    DeriveType m_derive;

    bool GetExtKey(const SigningProvider& arg, CExtKey& ret) const
    {
        CKey key;
        if (!arg.GetKey(m_root_extkey.pubkey.GetID(), key)) return false;
        ret.nDepth = m_root_extkey.nDepth;
        std::copy(m_root_extkey.vchFingerprint, m_root_extkey.vchFingerprint + sizeof(ret.vchFingerprint), ret.vchFingerprint);
        ret.nChild = m_root_extkey.nChild;
        ret.chaincode = m_root_extkey.chaincode;
        ret.key = key;
        return true;
    }

    // Derives the last xprv
    bool GetDerivedExtKey(const SigningProvider& arg, CExtKey& xprv, CExtKey& last_hardened) const
    {
        if (!GetExtKey(arg, xprv)) return false;
        for (auto entry : m_path.path) {
            if (!xprv.Derive(xprv, entry)) return false;
            if (entry >> 31) {
                last_hardened = xprv;
            }
        }
        return true;
    }

    bool IsHardened() const
    {
        if (m_derive == DeriveType::HARDENED) return true;
        for (auto entry : m_path.path) {
            if (entry >> 31) return true;
        }
        return false;
    }

public:
    BIP32PubkeyProvider(uint32_t exp_index, const CExtPubKey& extkey, HDKeyPath path, DeriveType derive) : PubkeyProvider(exp_index), m_root_extkey(extkey), m_path(std::move(path)), m_derive(derive) {}
    bool IsRange() const override { return m_derive != DeriveType::NO; }
    size_t GetSize() const override { return 33; }
    bool GetPubKey(int pos, const SigningProvider& arg, CPubKey& key_out, KeyOriginInfo& final_info_out, const DescriptorCache* read_cache = nullptr, DescriptorCache* write_cache = nullptr) const override
    {
        // Info of parent of the to be derived pubkey
        KeyOriginInfo parent_info;
        CKeyID keyid = m_root_extkey.pubkey.GetID();
        std::copy(keyid.begin(), keyid.begin() + sizeof(parent_info.fingerprint), parent_info.fingerprint);
        parent_info.hdkeypath = m_path;

        // Info of the derived key itself which is copied out upon successful completion
        KeyOriginInfo final_info_out_tmp = parent_info;
        if (m_derive == DeriveType::UNHARDENED) final_info_out_tmp.hdkeypath.path.push_back((uint32_t)pos);
        if (m_derive == DeriveType::HARDENED) final_info_out_tmp.hdkeypath.path.push_back(((uint32_t)pos) | 0x80000000L);

        // Derive keys or fetch them from cache
        CExtPubKey final_extkey = m_root_extkey;
        CExtPubKey parent_extkey = m_root_extkey;
        CExtPubKey last_hardened_extkey;
        bool der = true;
        if (read_cache) {
            if (!read_cache->GetCachedDerivedExtPubKey(m_expr_index, pos, final_extkey)) {
                if (m_derive == DeriveType::HARDENED) return false;
                // Try to get the derivation parent
                if (!read_cache->GetCachedParentExtPubKey(m_expr_index, parent_extkey)) return false;
                final_extkey = parent_extkey;
                if (m_derive == DeriveType::UNHARDENED) der = parent_extkey.Derive(final_extkey, pos);
            }
        } else if (IsHardened()) {
            CExtKey xprv;
            CExtKey lh_xprv;
            if (!GetDerivedExtKey(arg, xprv, lh_xprv)) return false;
            parent_extkey = xprv.Neuter();
            if (m_derive == DeriveType::UNHARDENED) der = xprv.Derive(xprv, pos);
            if (m_derive == DeriveType::HARDENED) der = xprv.Derive(xprv, pos | 0x80000000UL);
            final_extkey = xprv.Neuter();
            if (lh_xprv.key.IsValid()) {
                last_hardened_extkey = lh_xprv.Neuter();
            }
        } else {
            for (auto entry : m_path.path) {
                if (!parent_extkey.Derive(parent_extkey, entry)) return false;
            }
            final_extkey = parent_extkey;
            if (m_derive == DeriveType::UNHARDENED) der = parent_extkey.Derive(final_extkey, pos);
            assert(m_derive != DeriveType::HARDENED);
        }
        if (!der) return false;

        final_info_out = final_info_out_tmp;
        key_out = final_extkey.pubkey;

        if (write_cache) {
            // Only cache parent if there is any unhardened derivation
            if (m_derive != DeriveType::HARDENED) {
                write_cache->CacheParentExtPubKey(m_expr_index, parent_extkey);
                // Cache last hardened xpub if we have it
                if (last_hardened_extkey.pubkey.IsValid()) {
                    write_cache->CacheLastHardenedExtPubKey(m_expr_index, last_hardened_extkey);
                }
            } else if (final_info_out.hdkeypath.path.size() > 0) {
                write_cache->CacheDerivedExtPubKey(m_expr_index, pos, final_extkey);
            }
        }

        return true;
    }
    bool GetKeyOrigin(int pos, KeyOriginInfo& final_info_out) const override
    {
        // Info of parent of the to be derived pubkey
        KeyOriginInfo parent_info;
        CKeyID keyid = m_root_extkey.pubkey.GetID();
        std::copy(keyid.begin(), keyid.begin() + sizeof(parent_info.fingerprint), parent_info.fingerprint);
        parent_info.hdkeypath = m_path;

        // Info of the derived key itself which is copied out upon successful completion
        KeyOriginInfo final_info_out_tmp = parent_info;
        if (m_derive == DeriveType::UNHARDENED) final_info_out_tmp.hdkeypath.path.push_back((uint32_t)pos);
        if (m_derive == DeriveType::HARDENED) final_info_out_tmp.hdkeypath.path.push_back(((uint32_t)pos) | 0x80000000L);

        final_info_out = final_info_out_tmp;

        return true;
    }
    std::string ToString() const override
    {
        std::string ret = EncodeExtPubKey(m_root_extkey) + FormatHDKeypath(m_path);
        if (IsRange()) {
            ret += "/*";
            if (m_derive == DeriveType::HARDENED) ret += '\'';
        }
        return ret;
    }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const override
    {
        CExtKey key;
        if (!GetExtKey(arg, key)) return false;
        out = EncodeExtKey(key) + FormatHDKeypath(m_path);
        if (IsRange()) {
            out += "/*";
            if (m_derive == DeriveType::HARDENED) out += '\'';
        }
        return true;
    }
    bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache) const override
    {
        // For hardened derivation type, just return the typical string, nothing to normalize
        if (m_derive == DeriveType::HARDENED) {
            out = ToString();
            return true;
        }
        // Step backwards to find the last hardened step in the path
        int i = (int)m_path.path.size() - 1;
        for (; i >= 0; --i) {
            if (m_path.path.at(i) >> 31) {
                break;
            }
        }
        // Either no derivation or all unhardened derivation
        if (i == -1) {
            out = ToString();
            return true;
        }
        // Get the path to the last hardened stup
        KeyOriginInfo origin;
        int k = 0;
        for (; k <= i; ++k) {
            // Add to the path
            origin.hdkeypath.path.push_back(m_path.path.at(k));
        }
        // Build the remaining path
        HDKeyPath end_path;
        for (; k < (int)m_path.path.size(); ++k) {
            end_path.path.push_back(m_path.path.at(k));
        }
        // Get the fingerprint
        CKeyID id = m_root_extkey.pubkey.GetID();
        std::copy(id.begin(), id.begin() + 4, origin.fingerprint);

        CExtPubKey xpub;
        CExtKey lh_xprv;
        // If we have the cache, just get the parent xpub
        if (cache != nullptr) {
            cache->GetCachedLastHardenedExtPubKey(m_expr_index, xpub);
        }
        if (!xpub.pubkey.IsValid()) {
            // Cache miss, or nor cache, or need privkey
            CExtKey xprv;
            if (!GetDerivedExtKey(arg, xprv, lh_xprv)) return false;
            xpub = lh_xprv.Neuter();
        }
        assert(xpub.pubkey.IsValid());

        // Build the string
        std::string origin_str = HexStr(origin.fingerprint) + FormatHDKeypath(origin.hdkeypath);
        out = "[" + origin_str + "]" + EncodeExtPubKey(xpub) + FormatHDKeypath(end_path);
        if (IsRange()) {
            out += "/*";
            assert(m_derive == DeriveType::UNHARDENED);
        }
        return true;
    }
    bool GetPrivKey(int pos, const SigningProvider& arg, CKey& key) const override
    {
        CExtKey extkey;
        CExtKey dummy;
        if (!GetDerivedExtKey(arg, extkey, dummy)) return false;
        if (m_derive == DeriveType::UNHARDENED && !extkey.Derive(extkey, pos)) return false;
        if (m_derive == DeriveType::HARDENED && !extkey.Derive(extkey, pos | 0x80000000UL)) return false;
        key = extkey.key;
        return true;
    }
};

#endif // BITCOIN_SCRIPT_PUBKEYPROVIDER_H
