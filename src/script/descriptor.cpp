// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/descriptor.h>

#include <key_io.h>
#include <mw/crypto/SecretKeys.h>
#include <pubkey.h>
#include <script/miniscript.h>
#include <script/pubkeyprovider.h>
#include <script/script.h>
#include <script/standard.h>

#include <span.h>
#include <util/bip32.h>
#include <util/spanparsing.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/vector.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

////////////////////////////////////////////////////////////////////////////
// Checksum                                                               //
////////////////////////////////////////////////////////////////////////////

// This section implements a checksum algorithm for descriptors with the
// following properties:
// * Mistakes in a descriptor string are measured in "symbol errors". The higher
//   the number of symbol errors, the harder it is to detect:
//   * An error substituting a character from 0123456789()[],'/*abcdefgh@:$%{} for
//     another in that set always counts as 1 symbol error.
//     * Note that hex encoded keys are covered by these characters. Xprvs and
//       xpubs use other characters too, but already have their own checksum
//       mechanism.
//     * Function names like "multi()" use other characters, but mistakes in
//       these would generally result in an unparsable descriptor.
//   * A case error always counts as 1 symbol error.
//   * Any other 1 character substitution error counts as 1 or 2 symbol errors.
// * Any 1 symbol error is always detected.
// * Any 2 or 3 symbol error in a descriptor of up to 49154 characters is always detected.
// * Any 4 symbol error in a descriptor of up to 507 characters is always detected.
// * Any 5 symbol error in a descriptor of up to 77 characters is always detected.
// * Is optimized to minimize the chance a 5 symbol error in a descriptor up to 387 characters is undetected
// * Random errors have a chance of 1 in 2**40 of being undetected.
//
// These properties are achieved by expanding every group of 3 (non checksum) characters into
// 4 GF(32) symbols, over which a cyclic code is defined.

/*
 * Interprets c as 8 groups of 5 bits which are the coefficients of a degree 8 polynomial over GF(32),
 * multiplies that polynomial by x, computes its remainder modulo a generator, and adds the constant term val.
 *
 * This generator is G(x) = x^8 + {30}x^7 + {23}x^6 + {15}x^5 + {14}x^4 + {10}x^3 + {6}x^2 + {12}x + {9}.
 * It is chosen to define an cyclic error detecting code which is selected by:
 * - Starting from all BCH codes over GF(32) of degree 8 and below, which by construction guarantee detecting
 *   3 errors in windows up to 19000 symbols.
 * - Taking all those generators, and for degree 7 ones, extend them to degree 8 by adding all degree-1 factors.
 * - Selecting just the set of generators that guarantee detecting 4 errors in a window of length 512.
 * - Selecting one of those with best worst-case behavior for 5 errors in windows of length up to 512.
 *
 * The generator and the constants to implement it can be verified using this Sage code:
 *   B = GF(2) # Binary field
 *   BP.<b> = B[] # Polynomials over the binary field
 *   F_mod = b**5 + b**3 + 1
 *   F.<f> = GF(32, modulus=F_mod, repr='int') # GF(32) definition
 *   FP.<x> = F[] # Polynomials over GF(32)
 *   E_mod = x**3 + x + F.fetch_int(8)
 *   E.<e> = F.extension(E_mod) # Extension field definition
 *   alpha = e**2743 # Choice of an element in extension field
 *   for p in divisors(E.order() - 1): # Verify alpha has order 32767.
 *       assert((alpha**p == 1) == (p % 32767 == 0))
 *   G = lcm([(alpha**i).minpoly() for i in [1056,1057,1058]] + [x + 1])
 *   print(G) # Print out the generator
 *   for i in [1,2,4,8,16]: # Print out {1,2,4,8,16}*(G mod x^8), packed in hex integers.
 *       v = 0
 *       for coef in reversed((F.fetch_int(i)*(G % x**8)).coefficients(sparse=True)):
 *           v = v*32 + coef.integer_representation()
 *       print("0x%x" % v)
 */
uint64_t PolyMod(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
}

std::string DescriptorChecksum(const Span<const char>& span)
{
    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    static std::string INPUT_CHARSET =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    /** The character set for the checksum itself (same as bech32). */
    static std::string CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    for (auto ch : span) {
        auto pos = INPUT_CHARSET.find(ch);
        if (pos == std::string::npos) return "";
        c = PolyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
        cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
        if (++clscount == 3) {
            // Emit an extra symbol representing the group numbers, for every 3 characters.
            c = PolyMod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) c = PolyMod(c, cls);
    for (int j = 0; j < 8; ++j) c = PolyMod(c, 0); // Shift further to determine the checksum.
    c ^= 1; // Prevent appending zeroes from not affecting the checksum.

    std::string ret(8, ' ');
    for (int j = 0; j < 8; ++j) ret[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
    return ret;
}

std::string AddChecksum(const std::string& str) { return str + "#" + DescriptorChecksum(str); }

/** Base class for all Descriptor implementations. */
class DescriptorImpl : public Descriptor
{
protected:
    //! Public key arguments for this descriptor (size 1 for PK, PKH, WPKH, MWEB; any size for WSH and Multisig).
    const std::vector<std::unique_ptr<PubkeyProvider>> m_pubkey_args;
    //! The string name of the descriptor function.
    const std::string m_name;

    //! The sub-descriptor arguments (empty for everything but SH and WSH).
    //! In doc/descriptors.m this is referred to as SCRIPT expressions sh(SCRIPT)
    //! and wsh(SCRIPT), and distinct from KEY expressions and ADDR expressions.
    //! Subdescriptors can only ever generate a single script.
    const std::vector<std::unique_ptr<DescriptorImpl>> m_subdescriptor_args;

    //! Return a serialization of anything except pubkey and script arguments, to be prepended to those.
    virtual std::string ToStringExtra() const { return ""; }

    /** A helper function to construct the scripts for this descriptor.
     *
     *  This function is invoked once by ExpandHelper.
     *
     *  @param pubkeys The evaluations of the m_pubkey_args field.
     *  @param scripts The evaluations of m_subdescriptor_args (one for each m_subdescriptor_args element).
     *  @param out A FlatSigningProvider to put scripts or public keys in that are necessary to the solver.
     *             The origin info of the provided pubkeys is automatically added.
     *  @return A vector with scriptPubKeys for this descriptor.
     */
    virtual std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& pubkeys, Span<const CScript> scripts, FlatSigningProvider& out) const = 0;

public:
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args() {}
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, std::unique_ptr<DescriptorImpl> script, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args(Vector(std::move(script))) {}
    DescriptorImpl(std::vector<std::unique_ptr<PubkeyProvider>> pubkeys, std::vector<std::unique_ptr<DescriptorImpl>> scripts, const std::string& name) : m_pubkey_args(std::move(pubkeys)), m_name(name), m_subdescriptor_args(std::move(scripts)) {}

    enum class StringType
    {
        PUBLIC,
        PRIVATE,
        NORMALIZED,
    };

    bool IsSolvable() const override
    {
        for (const auto& arg : m_subdescriptor_args) {
            if (!arg->IsSolvable()) return false;
        }
        return true;
    }

    bool IsRange() const override
    {
        for (const auto& pubkey : m_pubkey_args) {
            if (pubkey->IsRange()) return true;
        }
        for (const auto& arg : m_subdescriptor_args) {
            if (arg->IsRange()) return true;
        }
        return false;
    }

    virtual bool ToStringSubScriptHelper(const SigningProvider* arg, std::string& ret, const StringType type, const DescriptorCache* cache = nullptr) const
    {
        size_t pos = 0;
        for (const auto& scriptarg : m_subdescriptor_args) {
            if (pos++) ret += ",";
            std::string tmp;
            if (!scriptarg->ToStringHelper(arg, tmp, type, cache)) return false;
            ret += tmp;
        }
        return true;
    }

    virtual bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type, const DescriptorCache* cache = nullptr) const
    {
        std::string extra = ToStringExtra();
        size_t pos = extra.size() > 0 ? 1 : 0;
        std::string ret = m_name + "(" + extra;
        for (const auto& pubkey : m_pubkey_args) {
            if (pos++) ret += ",";
            std::string tmp;
            switch (type) {
                case StringType::NORMALIZED:
                    if (!pubkey->ToNormalizedString(*arg, tmp, cache)) return false;
                    break;
                case StringType::PRIVATE:
                    if (!pubkey->ToPrivateString(*arg, tmp)) return false;
                    break;
                case StringType::PUBLIC:
                    tmp = pubkey->ToString();
                    break;
            }
            ret += tmp;
        }
        std::string subscript;
        if (!ToStringSubScriptHelper(arg, subscript, type, cache)) return false;
        if (pos && subscript.size()) ret += ',';
        out = std::move(ret) + std::move(subscript) + ")";
        return true;
    }

    std::string ToString() const final
    {
        std::string ret;
        ToStringHelper(nullptr, ret, StringType::PUBLIC);
        return AddChecksum(ret);
    }

    bool ToPrivateString(const SigningProvider& arg, std::string& out) const override
    {
        bool ret = ToStringHelper(&arg, out, StringType::PRIVATE);
        out = AddChecksum(out);
        return ret;
    }

    bool ToNormalizedString(const SigningProvider& arg, std::string& out, const DescriptorCache* cache) const final
    {
        bool ret = ToStringHelper(&arg, out, StringType::NORMALIZED, cache);
        out = AddChecksum(out);
        return ret;
    }

    bool ExpandHelper(int pos, const SigningProvider& arg, const DescriptorCache* read_cache, std::vector<GenericAddress>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache) const
    {
        std::vector<std::pair<CPubKey, KeyOriginInfo>> entries;
        entries.reserve(m_pubkey_args.size());

        // Construct temporary data in `entries`, `subscripts`, and `subprovider` to avoid producing output in case of failure.
        for (const auto& p : m_pubkey_args) {
            entries.emplace_back();
            if (!p->GetPubKey(pos, arg, entries.back().first, entries.back().second, read_cache, write_cache)) return false;
        }
        std::vector<CScript> subscripts;
        FlatSigningProvider subprovider;
        for (const auto& subarg : m_subdescriptor_args) {
            std::vector<GenericAddress> outscripts;
            if (!subarg->ExpandHelper(pos, arg, read_cache, outscripts, subprovider, write_cache)) return false;
            assert(outscripts.size() == 1);
            subscripts.emplace_back(outscripts[0].GetScript());
        }
        out.Merge(std::move(subprovider));

        std::vector<CPubKey> pubkeys;
        pubkeys.reserve(entries.size());
        for (auto& entry : entries) {
            pubkeys.push_back(entry.first);
            out.origins.emplace(entry.first.GetID(), std::make_pair<CPubKey, KeyOriginInfo>(CPubKey(entry.first), std::move(entry.second)));
        }

        output_scripts = MakeScripts(pubkeys, Span{subscripts}, out);
        return true;
    }

    bool Expand(int pos, const SigningProvider& provider, std::vector<GenericAddress>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const override
    {
        return ExpandHelper(pos, provider, nullptr, output_scripts, out, write_cache);
    }

    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<GenericAddress>& output_scripts, FlatSigningProvider& out) const override
    {
        return ExpandHelper(pos, DUMMY_SIGNING_PROVIDER, &read_cache, output_scripts, out, nullptr);
    }

    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const override
    {
        for (const auto& p : m_pubkey_args) {
            CKey key;
            if (!p->GetPrivKey(pos, provider, key)) continue;
            out.keys.emplace(key.GetPubKey().GetID(), key);
        }
        for (const auto& arg : m_subdescriptor_args) {
            arg->ExpandPrivate(pos, provider, out);
        }
    }

    std::optional<OutputType> GetOutputType() const override { return std::nullopt; }
};

/** A parsed addr(A) descriptor. */
class AddressDescriptor final : public DescriptorImpl
{
    const CTxDestination m_destination;
protected:
    std::string ToStringExtra() const override { return EncodeDestination(m_destination); }
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>&, Span<const CScript>, FlatSigningProvider&) const override { return Vector(GenericAddress(m_destination)); }
public:
    AddressDescriptor(CTxDestination destination) : DescriptorImpl({}, "addr"), m_destination(std::move(destination)) {}
    bool IsSolvable() const final { return false; }

    std::optional<OutputType> GetOutputType() const override
    {
        return OutputTypeFromDestination(m_destination);
    }
    bool IsSingleType() const final { return true; }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const final { return false; }
};

/** A parsed raw(H) descriptor. */
class RawDescriptor final : public DescriptorImpl
{
    const CScript m_script;
protected:
    std::string ToStringExtra() const override { return HexStr(m_script); }
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>&, Span<const CScript>, FlatSigningProvider&) const override { return Vector(GenericAddress(m_script)); }
public:
    RawDescriptor(CScript script) : DescriptorImpl({}, "raw"), m_script(std::move(script)) {}
    bool IsSolvable() const final { return false; }

    std::optional<OutputType> GetOutputType() const override
    {
        CTxDestination dest;
        ExtractDestination(m_script, dest);
        return OutputTypeFromDestination(dest);
    }
    bool IsSingleType() const final { return true; }
    bool ToPrivateString(const SigningProvider& arg, std::string& out) const final { return false; }
};

/** A parsed pk(P) descriptor. */
class PKDescriptor final : public DescriptorImpl
{
private:
    const bool m_xonly;
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider&) const override
    {
        if (m_xonly) {
            CScript script = CScript() << ToByteVector(XOnlyPubKey(keys[0])) << OP_CHECKSIG;
            return Vector(GenericAddress(std::move(script)));
        } else {
            return Vector(GenericAddress(GetScriptForRawPubKey(keys[0])));
        }
    }
public:
    PKDescriptor(std::unique_ptr<PubkeyProvider> prov, bool xonly = false) : DescriptorImpl(Vector(std::move(prov)), "pk"), m_xonly(xonly) {}
    bool IsSingleType() const final { return true; }
};

/** A parsed pkh(P) descriptor. */
class PKHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out) const override
    {
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);
        return Vector(GenericAddress(PKHash(id)));
    }
public:
    PKHDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "pkh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::LEGACY; }
    bool IsSingleType() const final { return true; }
};

/** A parsed wpkh(P) descriptor. */
class WPKHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out) const override
    {
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);
        return Vector(GenericAddress(WitnessV0KeyHash(id)));
    }
public:
    WPKHDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "wpkh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32; }
    bool IsSingleType() const final { return true; }
};

/** A parsed mweb(P) descriptor. */
class MWEBDescriptor final : public DescriptorImpl
{
public:
    enum class Type
    {
        RANGE,
        SINGLE_INDEX,
        SINGLE_SUBADDR,
    };

private:
    //! The master scan secret key
    SecretKey m_master_scan_secret;
    //! The (optional) index of the MWEB subaddress represented by this descriptor.
    std::optional<uint32_t> m_mweb_index;
    //! Descriptor mode for MWEB spend keys and range handling.
    Type m_type;

protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out) const override
    {
        return std::vector<GenericAddress>{};
    }

    bool ToStringSubScriptHelper(const SigningProvider* arg, std::string& ret, const StringType type, const DescriptorCache* cache = nullptr) const override
    {
        if (m_type == Type::RANGE) {
            ret = "*";
        } else if (m_type == Type::SINGLE_INDEX && m_mweb_index) {
            ret = strprintf("%i", *m_mweb_index);
        }
        return true;
    }

public:
    // 'providers' will either be:
    //   * a single xpub where child 0' is the master scan key, and child 1' is the master spend key
    //   * 2 pubkeys where the first is the scan pubkey and the second is the spend pubkey of a single stealth address
    MWEBDescriptor(std::unique_ptr<PubkeyProvider> master_scan_pk_provider, std::unique_ptr<PubkeyProvider> spend_pk_provider, CKey master_scan_key, const Type type, const std::optional<uint32_t>& mweb_index)
        : DescriptorImpl(Vector(std::move(master_scan_pk_provider), std::move(spend_pk_provider)), "mweb"),
          m_master_scan_secret(master_scan_key.begin()),
          m_mweb_index(mweb_index),
          m_type(type) {}

    bool IsRange() const final { return m_type == Type::RANGE; }
    std::optional<OutputType> GetOutputType() const final { return OutputType::MWEB; }
    bool IsSingleType() const final { return true; }

    bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type, const DescriptorCache* cache = nullptr) const final
    {
        std::string scan_key_str;
        switch (type) {
            case StringType::PRIVATE:
                if (!m_pubkey_args[0]->ToPrivateString(*arg, scan_key_str)) return false;
                break;
            case StringType::NORMALIZED:
            case StringType::PUBLIC: {
                CKey master_scan_key;
                master_scan_key.Set(m_master_scan_secret.vec().begin(), m_master_scan_secret.vec().end(), true);

                std::string origin_str = "";
                KeyOriginInfo origin_info;
                if (m_pubkey_args[0]->GetKeyOrigin(-1, origin_info)) {
                    origin_str = "[" + HexStr(origin_info.fingerprint) + FormatHDKeypath(origin_info.hdkeypath) + "]";
                }

                scan_key_str = origin_str + EncodeSecret(master_scan_key);
                break;
            }
        }

        std::string spend_key_str;
        switch (type) {
            case StringType::NORMALIZED:
                if (!m_pubkey_args[1]->ToNormalizedString(*arg, spend_key_str, cache)) return false;
                break;
            case StringType::PRIVATE:
                if (!m_pubkey_args[1]->ToPrivateString(*arg, spend_key_str)) return false;
                break;
            case StringType::PUBLIC:
                spend_key_str = m_pubkey_args[1]->ToString();
                break;
        }

        std::string subscript;
        if (!ToStringSubScriptHelper(arg, subscript, type, cache)) return false;
        if (!subscript.empty()) subscript = ',' + subscript;

        out = "mweb(" + scan_key_str + "," + spend_key_str + subscript + ")";
        return true;
    }

    bool ExpandHelper(int pos, const SigningProvider& provider, const DescriptorCache* read_cache, std::vector<GenericAddress>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache) const
    {
        output_scripts.clear();
        const bool is_subaddr_spend = m_type == Type::SINGLE_SUBADDR;
        int effective_pos = pos;
        if (m_type == Type::SINGLE_INDEX && m_mweb_index) {
            effective_pos = *m_mweb_index;
        }

        out.mweb_master_scan_key = CKey();
        out.mweb_master_scan_key->Set(m_master_scan_secret.vec().begin(), m_master_scan_secret.vec().end(), true);
        
        KeyOriginInfo master_scan_origin;
        if (m_pubkey_args[0]->GetKeyOrigin(-1, master_scan_origin)) {
            out.mweb_master_scan_origin = master_scan_origin;
            CPubKey master_scan_pk(PublicKey::From(m_master_scan_secret).vec());
            out.pubkeys.emplace(master_scan_pk.GetID(), master_scan_pk);
            out.origins.emplace(master_scan_pk.GetID(), std::make_pair<CPubKey, KeyOriginInfo>(std::move(master_scan_pk), KeyOriginInfo(master_scan_origin)));
        }

        if (pos == -1) {
            CPubKey master_scan_pk(PublicKey::From(m_master_scan_secret).vec());
            out.pubkeys.emplace(master_scan_pk.GetID(), master_scan_pk);

            if (out.mweb_master_scan_origin) {
                out.origins.emplace(master_scan_pk.GetID(), std::make_pair<CPubKey, KeyOriginInfo>(std::move(master_scan_pk), KeyOriginInfo(*out.mweb_master_scan_origin)));
            }

            return true;
        }

        std::optional<PublicKey> spend_pubkey;
        KeyOriginInfo spend_origin;
        if (is_subaddr_spend) {
            CPubKey subaddr_spend_pk;
            if (!m_pubkey_args[1]->GetPubKey(-1, provider, subaddr_spend_pk, spend_origin, read_cache, write_cache)) return false;
            spend_pubkey = PublicKey(subaddr_spend_pk.begin());
        } else {
            spend_pubkey = GetMasterSpendPubKey(provider, read_cache, write_cache);
            if (!spend_pubkey) return false;
        }

        if (!is_subaddr_spend) {
            out.mweb_master_spend_pk = CPubKey(spend_pubkey->vec());
            if (m_pubkey_args[1]->GetKeyOrigin(-1, spend_origin)) {
                out.mweb_master_spend_origin = spend_origin;
            }
        }

        if (pos == -2) {
            CPubKey spend_pk(spend_pubkey->vec());
            out.pubkeys.emplace(spend_pubkey->GetID(), spend_pk);

            if (m_pubkey_args[1]->GetKeyOrigin(-1, spend_origin)) {
                out.origins.emplace(spend_pubkey->GetID(), std::make_pair<CPubKey, KeyOriginInfo>(CPubKey(spend_pk), std::move(spend_origin)));
            }

            return true;
        }

        if (is_subaddr_spend) {
            PublicKey Bi = *spend_pubkey;
            PublicKey Ai = Bi.Mul(m_master_scan_secret);

            output_scripts = {StealthAddress(Ai, Bi)};

            CKeyID address_key_id = Bi.GetID();
            CPubKey address_pk(Bi.vec());
            out.pubkeys.emplace(address_key_id, address_pk);

            if (m_pubkey_args[1]->GetKeyOrigin(-1, spend_origin)) {
                out.origins.emplace(address_key_id, std::make_pair<CPubKey, KeyOriginInfo>(CPubKey(address_pk), std::move(spend_origin)));
            }

            return true;
        }

        StealthAddress stealth_address = mw::DeriveSubaddress(*spend_pubkey, m_master_scan_secret, effective_pos);

        output_scripts = {stealth_address};

        CKeyID address_key_id = stealth_address.B().GetID();
        CPubKey address_pk(stealth_address.B().vec());
        out.pubkeys.emplace(address_key_id, address_pk);

        if (out.mweb_master_scan_origin) {
            KeyOriginInfo key_origin;
            std::copy(out.mweb_master_scan_origin->fingerprint, out.mweb_master_scan_origin->fingerprint + sizeof(key_origin.fingerprint), key_origin.fingerprint);
            key_origin.hdkeypath.mweb_index = effective_pos;
            out.origins.emplace(address_key_id, std::make_pair<CPubKey, KeyOriginInfo>(std::move(address_pk), std::move(key_origin)));
        }

        return true;
    }

    bool Expand(int pos, const SigningProvider& provider, std::vector<GenericAddress>& output_scripts, FlatSigningProvider& out, DescriptorCache* write_cache = nullptr) const final
    {
        return ExpandHelper(pos, provider, nullptr, output_scripts, out, write_cache);
    }

    bool ExpandFromCache(int pos, const DescriptorCache& read_cache, std::vector<GenericAddress>& output_scripts, FlatSigningProvider& out) const final
    {
        return ExpandHelper(pos, DUMMY_SIGNING_PROVIDER, &read_cache, output_scripts, out, nullptr);
    }

    void ExpandPrivate(int pos, const SigningProvider& provider, FlatSigningProvider& out) const final
    {
        CKey master_scan_key;
        master_scan_key.Set(m_master_scan_secret.vec().begin(), m_master_scan_secret.vec().end(), true);
        out.mweb_master_scan_key = master_scan_key;

        if (pos == -1) {
            return;
        }

        if (m_type == Type::SINGLE_SUBADDR) {
            CKey spend_key;
            if (m_pubkey_args[1]->GetPrivKey(-1, provider, spend_key)) {
                out.keys.emplace(spend_key.GetPubKey().GetID(), spend_key);
            }
            return;
        }

        int effective_pos = pos;
        if (m_type == Type::SINGLE_INDEX && m_mweb_index) {
            effective_pos = *m_mweb_index;
        }

        std::optional<SecretKey> master_spend_secret = GetMasterSpendKey(provider);
        if (master_spend_secret.has_value()) {
            if (pos == -2) {
                CKey master_spend_key;
                master_spend_key.Set(master_spend_secret->vec().begin(), master_spend_secret->vec().end(), true);
                out.keys.emplace(master_spend_key.GetPubKey().GetID(), master_spend_key);
                return;
            }

            SecretKey subaddr_spend_key = mw::DeriveSubaddressSpendKey(*master_spend_secret, m_master_scan_secret, effective_pos);

            CKey key;
            key.Set(subaddr_spend_key.vec().begin(), subaddr_spend_key.vec().end(), true);
            out.keys.emplace(key.GetPubKey().GetID(), key);
        }
    }

private:
    std::optional<PublicKey> GetMasterSpendPubKey(const SigningProvider& signing_provider, const DescriptorCache* read_cache, DescriptorCache* write_cache) const
    {
        CPubKey spend_pubkey;
        KeyOriginInfo origin_info;
        if (!m_pubkey_args[1]->GetPubKey(-1, signing_provider, spend_pubkey, origin_info, read_cache, write_cache)) return std::nullopt;
        return PublicKey(spend_pubkey.begin());
    }

    std::optional<SecretKey> GetMasterSpendKey(const SigningProvider& signing_provider) const
    {
        CKey spend_key;
        if (!m_pubkey_args[1]->GetPrivKey(-1, signing_provider, spend_key)) return std::nullopt;
        return SecretKey(spend_key.begin());
    }
};

/** A parsed combo(P) descriptor. */
class ComboDescriptor final : public DescriptorImpl
{
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider& out) const override
    {
        std::vector<GenericAddress> ret;
        CKeyID id = keys[0].GetID();
        out.pubkeys.emplace(id, keys[0]);
        ret.emplace_back(GenericAddress(GetScriptForRawPubKey(keys[0]))); // P2PK
        ret.emplace_back(GenericAddress(PKHash(id))); // P2PKH
        if (keys[0].IsCompressed()) {
            CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(id));
            out.scripts.emplace(CScriptID(p2wpkh), p2wpkh);
            ret.emplace_back(GenericAddress(p2wpkh));
            ret.emplace_back(GenericAddress(ScriptHash(p2wpkh))); // P2SH-P2WPKH
        }
        return ret;
    }
public:
    ComboDescriptor(std::unique_ptr<PubkeyProvider> prov) : DescriptorImpl(Vector(std::move(prov)), "combo") {}
    bool IsSingleType() const final { return false; }
};

/** A parsed multi(...) or sortedmulti(...) descriptor */
class MultisigDescriptor final : public DescriptorImpl
{
    const int m_threshold;
    const bool m_sorted;
protected:
    std::string ToStringExtra() const override { return strprintf("%i", m_threshold); }
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider&) const override {
        if (m_sorted) {
            std::vector<CPubKey> sorted_keys(keys);
            std::sort(sorted_keys.begin(), sorted_keys.end());
            return Vector(GenericAddress(GetScriptForMultisig(m_threshold, sorted_keys)));
        }
        return Vector(GenericAddress(GetScriptForMultisig(m_threshold, keys)));
    }
public:
    MultisigDescriptor(int threshold, std::vector<std::unique_ptr<PubkeyProvider>> providers, bool sorted = false) : DescriptorImpl(std::move(providers), sorted ? "sortedmulti" : "multi"), m_threshold(threshold), m_sorted(sorted) {}
    bool IsSingleType() const final { return true; }
};

/** A parsed (sorted)multi_a(...) descriptor. Always uses x-only pubkeys. */
class MultiADescriptor final : public DescriptorImpl
{
    const int m_threshold;
    const bool m_sorted;
protected:
    std::string ToStringExtra() const override { return strprintf("%i", m_threshold); }
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript>, FlatSigningProvider&) const override {
        CScript ret;
        std::vector<XOnlyPubKey> xkeys;
        for (const auto& key : keys) xkeys.emplace_back(key);
        if (m_sorted) std::sort(xkeys.begin(), xkeys.end());
        ret << ToByteVector(xkeys[0]) << OP_CHECKSIG;
        for (size_t i = 1; i < keys.size(); ++i) {
            ret << ToByteVector(xkeys[i]) << OP_CHECKSIGADD;
        }
        ret << m_threshold << OP_NUMEQUAL;
        return Vector(GenericAddress(std::move(ret)));
    }
public:
    MultiADescriptor(int threshold, std::vector<std::unique_ptr<PubkeyProvider>> providers, bool sorted = false) : DescriptorImpl(std::move(providers), sorted ? "sortedmulti_a" : "multi_a"), m_threshold(threshold), m_sorted(sorted) {}
    bool IsSingleType() const final { return true; }
};

/** A parsed sh(...) descriptor. */
class SHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>&, Span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        auto ret = Vector(GenericAddress(ScriptHash(scripts[0])));
        if (ret.size()) out.scripts.emplace(CScriptID(scripts[0]), scripts[0]);
        return ret;
    }
public:
    SHDescriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "sh") {}

    std::optional<OutputType> GetOutputType() const override
    {
        assert(m_subdescriptor_args.size() == 1);
        if (m_subdescriptor_args[0]->GetOutputType() == OutputType::BECH32) return OutputType::P2SH_SEGWIT;
        return OutputType::LEGACY;
    }
    bool IsSingleType() const final { return true; }
};

/** A parsed wsh(...) descriptor. */
class WSHDescriptor final : public DescriptorImpl
{
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>&, Span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        auto ret = Vector(GenericAddress(WitnessV0ScriptHash(scripts[0])));
        if (ret.size()) out.scripts.emplace(CScriptID(scripts[0]), scripts[0]);
        return ret;
    }
public:
    WSHDescriptor(std::unique_ptr<DescriptorImpl> desc) : DescriptorImpl({}, std::move(desc), "wsh") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32; }
    bool IsSingleType() const final { return true; }
};

/** A parsed tr(...) descriptor. */
class TRDescriptor final : public DescriptorImpl
{
    std::vector<int> m_depths;
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        TaprootBuilder builder;
        assert(m_depths.size() == scripts.size());
        for (size_t pos = 0; pos < m_depths.size(); ++pos) {
            builder.Add(m_depths[pos], scripts[pos], TAPROOT_LEAF_TAPSCRIPT);
        }
        if (!builder.IsComplete()) return {};
        assert(keys.size() == 1);
        XOnlyPubKey xpk(keys[0]);
        if (!xpk.IsFullyValid()) return {};
        builder.Finalize(xpk);
        WitnessV1Taproot output = builder.GetOutput();
        out.tr_trees[output] = builder;
        out.pubkeys.emplace(keys[0].GetID(), keys[0]);
        return Vector(GenericAddress(output));
    }
    bool ToStringSubScriptHelper(const SigningProvider* arg, std::string& ret, const StringType type, const DescriptorCache* cache = nullptr) const override
    {
        if (m_depths.empty()) return true;
        std::vector<bool> path;
        for (size_t pos = 0; pos < m_depths.size(); ++pos) {
            if (pos) ret += ',';
            while ((int)path.size() <= m_depths[pos]) {
                if (path.size()) ret += '{';
                path.push_back(false);
            }
            std::string tmp;
            if (!m_subdescriptor_args[pos]->ToStringHelper(arg, tmp, type, cache)) return false;
            ret += tmp;
            while (!path.empty() && path.back()) {
                if (path.size() > 1) ret += '}';
                path.pop_back();
            }
            if (!path.empty()) path.back() = true;
        }
        return true;
    }
public:
    TRDescriptor(std::unique_ptr<PubkeyProvider> internal_key, std::vector<std::unique_ptr<DescriptorImpl>> descs, std::vector<int> depths) :
        DescriptorImpl(Vector(std::move(internal_key)), std::move(descs), "tr"), m_depths(std::move(depths))
    {
        assert(m_subdescriptor_args.size() == m_depths.size());
    }
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32M; }
    bool IsSingleType() const final { return true; }
};

/* We instantiate Miniscript here with a simple integer as key type.
 * The value of these key integers are an index in the
 * DescriptorImpl::m_pubkey_args vector.
 */

/**
 * The context for converting a Miniscript descriptor into a Script.
 */
class ScriptMaker {
    //! Keys contained in the Miniscript (the evaluation of DescriptorImpl::m_pubkey_args).
    const std::vector<CPubKey>& m_keys;

public:
    ScriptMaker(const std::vector<CPubKey>& keys LIFETIMEBOUND) : m_keys(keys) {}

    std::vector<unsigned char> ToPKBytes(uint32_t key) const {
        return {m_keys[key].begin(), m_keys[key].end()};
    }

    std::vector<unsigned char> ToPKHBytes(uint32_t key) const {
        auto id = m_keys[key].GetID();
        return {id.begin(), id.end()};
    }
};

/**
 * The context for converting a Miniscript descriptor to its textual form.
 */
class StringMaker {
    //! To convert private keys for private descriptors.
    const SigningProvider* m_arg;
    //! Keys contained in the Miniscript (a reference to DescriptorImpl::m_pubkey_args).
    const std::vector<std::unique_ptr<PubkeyProvider>>& m_pubkeys;
    //! Whether to serialize keys as private or public.
    bool m_private;

public:
    StringMaker(const SigningProvider* arg LIFETIMEBOUND, const std::vector<std::unique_ptr<PubkeyProvider>>& pubkeys LIFETIMEBOUND, bool priv)
        : m_arg(arg), m_pubkeys(pubkeys), m_private(priv) {}

    std::optional<std::string> ToString(uint32_t key) const
    {
        std::string ret;
        if (m_private) {
            if (!m_pubkeys[key]->ToPrivateString(*m_arg, ret)) return {};
        } else {
            ret = m_pubkeys[key]->ToString();
        }
        return ret;
    }
};

class MiniscriptDescriptor final : public DescriptorImpl
{
private:
    miniscript::NodeRef<uint32_t> m_node;

protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript> scripts,
                                     FlatSigningProvider& provider) const override
    {
        for (const auto& key : keys) provider.pubkeys.emplace(key.GetID(), key);
        return Vector(GenericAddress(m_node->ToScript(ScriptMaker(keys))));
    }

public:
    MiniscriptDescriptor(std::vector<std::unique_ptr<PubkeyProvider>> providers, miniscript::NodeRef<uint32_t> node)
        : DescriptorImpl(std::move(providers), "?"), m_node(std::move(node)) {}

    bool ToStringHelper(const SigningProvider* arg, std::string& out, const StringType type,
                        const DescriptorCache* cache = nullptr) const override
    {
        if (const auto res = m_node->ToString(StringMaker(arg, m_pubkey_args, type == StringType::PRIVATE))) {
            out = *res;
            return true;
        }
        return false;
    }

    bool IsSolvable() const override { return false; } // For now, mark these descriptors as non-solvable (as we don't have signing logic for them).
    bool IsSingleType() const final { return true; }
};

/** A parsed rawtr(...) descriptor. */
class RawTRDescriptor final : public DescriptorImpl
{
protected:
    std::vector<GenericAddress> MakeScripts(const std::vector<CPubKey>& keys, Span<const CScript> scripts, FlatSigningProvider& out) const override
    {
        assert(keys.size() == 1);
        XOnlyPubKey xpk(keys[0]);
        if (!xpk.IsFullyValid()) return {};
        WitnessV1Taproot output{xpk};
        return Vector(GenericAddress(output));
    }
public:
    RawTRDescriptor(std::unique_ptr<PubkeyProvider> output_key) : DescriptorImpl(Vector(std::move(output_key)), "rawtr") {}
    std::optional<OutputType> GetOutputType() const override { return OutputType::BECH32M; }
    bool IsSingleType() const final { return true; }
};

////////////////////////////////////////////////////////////////////////////
// Parser                                                                 //
////////////////////////////////////////////////////////////////////////////

enum class ParseScriptContext {
    TOP,     //!< Top-level context (script goes directly in scriptPubKey)
    P2SH,    //!< Inside sh() (script becomes P2SH redeemScript)
    P2WPKH,  //!< Inside wpkh() (no script, pubkey only)
    P2WSH,   //!< Inside wsh() (script becomes v0 witness script)
    P2TR,    //!< Inside tr() (either internal key, or BIP342 script leaf)
};

/** Parse a key path, being passed a split list of elements (the first element is ignored). */
[[nodiscard]] bool ParseKeyPath(const std::vector<Span<const char>>& split, KeyPath& out, std::string& error)
{
    for (size_t i = 1; i < split.size(); ++i) {
        Span<const char> elem = split[i];
        bool hardened = false;
        if (elem.size() > 0 && (elem[elem.size() - 1] == '\'' || elem[elem.size() - 1] == 'h')) {
            elem = elem.first(elem.size() - 1);
            hardened = true;
        }
        uint32_t p;
        if (!ParseUInt32(std::string(elem.begin(), elem.end()), &p)) {
            error = strprintf("Key path value '%s' is not a valid uint32", std::string(elem.begin(), elem.end()));
            return false;
        } else if (p > 0x7FFFFFFFUL) {
            error = strprintf("Key path value %u is out of range", p);
            return false;
        }
        out.push_back(p | (((uint32_t)hardened) << 31));
    }
    return true;
}

/** Parse a public key that excludes origin information. */
std::unique_ptr<PubkeyProvider> ParsePubkeyInner(uint32_t key_exp_index, const Span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error)
{
    using namespace spanparsing;

    bool permit_uncompressed = ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH;
    auto split = Split(sp, '/');
    std::string str(split[0].begin(), split[0].end());
    if (str.size() == 0) {
        error = "No key provided";
        return nullptr;
    }
    if (split.size() == 1) {
        if (IsHex(str)) {
            std::vector<unsigned char> data = ParseHex(str);
            CPubKey pubkey(data);
            if (pubkey.IsFullyValid()) {
                if (permit_uncompressed || pubkey.IsCompressed()) {
                    return std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey, false);
                } else {
                    error = "Uncompressed keys are not allowed";
                    return nullptr;
                }
            } else if (data.size() == 32 && ctx == ParseScriptContext::P2TR) {
                unsigned char fullkey[33] = {0x02};
                std::copy(data.begin(), data.end(), fullkey + 1);
                pubkey.Set(std::begin(fullkey), std::end(fullkey));
                if (pubkey.IsFullyValid()) {
                    return std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey, true);
                }
            }
            error = strprintf("Pubkey '%s' is invalid", str);
            return nullptr;
        }
        CKey key = DecodeSecret(str);
        if (key.IsValid()) {
            if (permit_uncompressed || key.IsCompressed()) {
                CPubKey pubkey = key.GetPubKey();
                out.keys.emplace(pubkey.GetID(), key);
                return std::make_unique<ConstPubkeyProvider>(key_exp_index, pubkey, ctx == ParseScriptContext::P2TR);
            } else {
                error = "Uncompressed keys are not allowed";
                return nullptr;
            }
        }
    }
    CExtKey extkey = DecodeExtKey(str);
    CExtPubKey extpubkey = DecodeExtPubKey(str);
    if (!extkey.key.IsValid() && !extpubkey.pubkey.IsValid()) {
        error = strprintf("key '%s' is not valid", str);
        return nullptr;
    }
    HDKeyPath hdkeypath;
    DeriveType type = DeriveType::NO;
    if (split.back() == Span{"*"}.first(1)) {
        split.pop_back();
        type = DeriveType::UNHARDENED;
    } else if (split.back() == Span{"*'"}.first(2) || split.back() == Span{"*h"}.first(2)) {
        split.pop_back();
        type = DeriveType::HARDENED;
    }
    if (!ParseKeyPath(split, hdkeypath.path, error)) return nullptr;
    if (extkey.key.IsValid()) {
        extpubkey = extkey.Neuter();
        out.keys.emplace(extpubkey.pubkey.GetID(), extkey.key);
    }
    return std::make_unique<BIP32PubkeyProvider>(key_exp_index, extpubkey, std::move(hdkeypath), type);
}

/** Parse a public key including origin information (if enabled). */
std::unique_ptr<PubkeyProvider> ParsePubkey(uint32_t key_exp_index, const Span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error)
{
    using namespace spanparsing;

    auto origin_split = Split(sp, ']');
    if (origin_split.size() > 2) {
        error = "Multiple ']' characters found for a single pubkey";
        return nullptr;
    }
    if (origin_split.size() == 1) return ParsePubkeyInner(key_exp_index, origin_split[0], ctx, out, error);
    if (origin_split[0].empty() || origin_split[0][0] != '[') {
        error = strprintf("Key origin start '[ character expected but not found, got '%c' instead",
                          origin_split[0].empty() ? /** empty, implies split char */ ']' : origin_split[0][0]);
        return nullptr;
    }
    auto slash_split = Split(origin_split[0].subspan(1), '/');
    if (slash_split[0].size() != 8) {
        error = strprintf("Fingerprint is not 4 bytes (%u characters instead of 8 characters)", slash_split[0].size());
        return nullptr;
    }
    std::string fpr_hex = std::string(slash_split[0].begin(), slash_split[0].end());
    if (!IsHex(fpr_hex)) {
        error = strprintf("Fingerprint '%s' is not hex", fpr_hex);
        return nullptr;
    }
    auto fpr_bytes = ParseHex(fpr_hex);
    KeyOriginInfo info;
    static_assert(sizeof(info.fingerprint) == 4, "Fingerprint must be 4 bytes");
    assert(fpr_bytes.size() == 4);
    std::copy(fpr_bytes.begin(), fpr_bytes.end(), info.fingerprint);
    if (!ParseKeyPath(slash_split, info.hdkeypath.path, error)) return nullptr;
    auto provider = ParsePubkeyInner(key_exp_index, origin_split[1], ctx, out, error);
    if (!provider) return nullptr;
    return std::make_unique<OriginPubkeyProvider>(key_exp_index, std::move(info), std::move(provider));
}

std::unique_ptr<PubkeyProvider> InferPubkey(const CPubKey& pubkey, ParseScriptContext, const SigningProvider& provider)
{
    std::unique_ptr<PubkeyProvider> key_provider = std::make_unique<ConstPubkeyProvider>(0, pubkey, false);
    KeyOriginInfo info;
    if (provider.GetKeyOrigin(pubkey.GetID(), info)) {
        return std::make_unique<OriginPubkeyProvider>(0, std::move(info), std::move(key_provider));
    }
    return key_provider;
}

std::unique_ptr<PubkeyProvider> InferXOnlyPubkey(const XOnlyPubKey& xkey, ParseScriptContext ctx, const SigningProvider& provider)
{
    unsigned char full_key[CPubKey::COMPRESSED_SIZE] = {0x02};
    std::copy(xkey.begin(), xkey.end(), full_key + 1);
    CPubKey pubkey(full_key);
    std::unique_ptr<PubkeyProvider> key_provider = std::make_unique<ConstPubkeyProvider>(0, pubkey, true);
    KeyOriginInfo info;
    if (provider.GetKeyOriginByXOnly(xkey, info)) {
        return std::make_unique<OriginPubkeyProvider>(0, std::move(info), std::move(key_provider));
    }
    return key_provider;
}

/**
 * The context for parsing a Miniscript descriptor (either from Script or from its textual representation).
 */
struct KeyParser {
    //! The Key type is an index in DescriptorImpl::m_pubkey_args
    using Key = uint32_t;
    //! Must not be nullptr if parsing from string.
    FlatSigningProvider* m_out;
    //! Must not be nullptr if parsing from Script.
    const SigningProvider* m_in;
    //! List of keys contained in the Miniscript.
    mutable std::vector<std::unique_ptr<PubkeyProvider>> m_keys;
    //! Used to detect key parsing errors within a Miniscript.
    mutable std::string m_key_parsing_error;

    KeyParser(FlatSigningProvider* out LIFETIMEBOUND, const SigningProvider* in LIFETIMEBOUND) : m_out(out), m_in(in) {}

    bool KeyCompare(const Key& a, const Key& b) const {
        return *m_keys.at(a) < *m_keys.at(b);
    }

    template<typename I> std::optional<Key> FromString(I begin, I end) const
    {
        assert(m_out);
        Key key = m_keys.size();
        auto pk = ParsePubkey(key, {&*begin, &*end}, ParseScriptContext::P2WSH, *m_out, m_key_parsing_error);
        if (!pk) return std::nullopt;
        m_keys.push_back(std::move(pk));
        return key;
    }

    std::optional<std::string> ToString(const Key& key) const
    {
        return m_keys.at(key)->ToString();
    }

    template<typename I> std::optional<Key> FromPKBytes(I begin, I end) const
    {
        assert(m_in);
        CPubKey pubkey(begin, end);
        if (pubkey.IsValid()) {
            Key key = m_keys.size();
            m_keys.push_back(InferPubkey(pubkey, ParseScriptContext::P2WSH, *m_in));
            return key;
        }
        return std::nullopt;
    }

    template<typename I> std::optional<Key> FromPKHBytes(I begin, I end) const
    {
        assert(end - begin == 20);
        assert(m_in);
        uint160 hash;
        std::copy(begin, end, hash.begin());
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (m_in->GetPubKey(keyid, pubkey)) {
            Key key = m_keys.size();
            m_keys.push_back(InferPubkey(pubkey, ParseScriptContext::P2WSH, *m_in));
            return key;
        }
        return std::nullopt;
    }
};

/** Parse a script in a particular context. */
std::unique_ptr<DescriptorImpl> ParseScript(uint32_t& key_exp_index, Span<const char>& sp, ParseScriptContext ctx, FlatSigningProvider& out, std::string& error)
{
    using namespace spanparsing;

    auto expr = Expr(sp);
    if (Func("pk", expr)) {
        auto pubkey = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (!pubkey) {
            error = strprintf("pk(): %s", error);
            return nullptr;
        }
        ++key_exp_index;
        return std::make_unique<PKDescriptor>(std::move(pubkey), ctx == ParseScriptContext::P2TR);
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH) && Func("pkh", expr)) {
        auto pubkey = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (!pubkey) {
            error = strprintf("pkh(): %s", error);
            return nullptr;
        }
        ++key_exp_index;
        return std::make_unique<PKHDescriptor>(std::move(pubkey));
    } else if (Func("pkh", expr)) {
        error = "Can only have pkh at top level, in sh(), or in wsh()";
        return nullptr;
    }
    if (ctx == ParseScriptContext::TOP && Func("combo", expr)) {
        auto pubkey = ParsePubkey(key_exp_index, expr, ctx, out, error);
        if (!pubkey) {
            error = strprintf("combo(): %s", error);
            return nullptr;
        }
        ++key_exp_index;
        return std::make_unique<ComboDescriptor>(std::move(pubkey));
    } else if (Func("combo", expr)) {
        error = "Can only have combo() at top level";
        return nullptr;
    }
    const bool multi = Func("multi", expr);
    const bool sortedmulti = !multi && Func("sortedmulti", expr);
    const bool multi_a = !(multi || sortedmulti) && Func("multi_a", expr);
    const bool sortedmulti_a = !(multi || sortedmulti || multi_a) && Func("sortedmulti_a", expr);
    if (((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH) && (multi || sortedmulti)) ||
        (ctx == ParseScriptContext::P2TR && (multi_a || sortedmulti_a))) {
        auto threshold = Expr(expr);
        uint32_t thres;
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        if (!ParseUInt32(std::string(threshold.begin(), threshold.end()), &thres)) {
            error = strprintf("Multi threshold '%s' is not valid", std::string(threshold.begin(), threshold.end()));
            return nullptr;
        }
        size_t script_size = 0;
        while (expr.size()) {
            if (!Const(",", expr)) {
                error = strprintf("Multi: expected ',', got '%c'", expr[0]);
                return nullptr;
            }
            auto arg = Expr(expr);
            auto pk = ParsePubkey(key_exp_index, arg, ctx, out, error);
            if (!pk) {
                error = strprintf("Multi: %s", error);
                return nullptr;
            }
            script_size += pk->GetSize() + 1;
            providers.emplace_back(std::move(pk));
            key_exp_index++;
        }
        if ((multi || sortedmulti) && (providers.empty() || providers.size() > MAX_PUBKEYS_PER_MULTISIG)) {
            error = strprintf("Cannot have %u keys in multisig; must have between 1 and %d keys, inclusive", providers.size(), MAX_PUBKEYS_PER_MULTISIG);
            return nullptr;
        } else if ((multi_a || sortedmulti_a) && (providers.empty() || providers.size() > MAX_PUBKEYS_PER_MULTI_A)) {
            error = strprintf("Cannot have %u keys in multi_a; must have between 1 and %d keys, inclusive", providers.size(), MAX_PUBKEYS_PER_MULTI_A);
            return nullptr;
        } else if (thres < 1) {
            error = strprintf("Multisig threshold cannot be %d, must be at least 1", thres);
            return nullptr;
        } else if (thres > providers.size()) {
            error = strprintf("Multisig threshold cannot be larger than the number of keys; threshold is %d but only %u keys specified", thres, providers.size());
            return nullptr;
        }
        if (ctx == ParseScriptContext::TOP) {
            if (providers.size() > 3) {
                error = strprintf("Cannot have %u pubkeys in bare multisig; only at most 3 pubkeys", providers.size());
                return nullptr;
            }
        }
        if (ctx == ParseScriptContext::P2SH) {
            // This limits the maximum number of compressed pubkeys to 15.
            if (script_size + 3 > MAX_SCRIPT_ELEMENT_SIZE) {
                error = strprintf("P2SH script is too large, %d bytes is larger than %d bytes", script_size + 3, MAX_SCRIPT_ELEMENT_SIZE);
                return nullptr;
            }
        }
        if (multi || sortedmulti) {
            return std::make_unique<MultisigDescriptor>(thres, std::move(providers), sortedmulti);
        } else {
            return std::make_unique<MultiADescriptor>(thres, std::move(providers), sortedmulti_a);
        }
    } else if (multi || sortedmulti) {
        error = "Can only have multi/sortedmulti at top level, in sh(), or in wsh()";
        return nullptr;
    } else if (multi_a || sortedmulti_a) {
        error = "Can only have multi_a/sortedmulti_a inside tr()";
        return nullptr;
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH) && Func("wpkh", expr)) {
        auto pubkey = ParsePubkey(key_exp_index, expr, ParseScriptContext::P2WPKH, out, error);
        if (!pubkey) {
            error = strprintf("wpkh(): %s", error);
            return nullptr;
        }
        key_exp_index++;
        return std::make_unique<WPKHDescriptor>(std::move(pubkey));
    } else if (Func("wpkh", expr)) {
        error = "Can only have wpkh() at top level or inside sh()";
        return nullptr;
    }

    // MWEB: There are currently 3 supported variants of "mweb" descriptors:
    // 1. mweb(master_scan, master_spend, *) - Ranged descriptor that represents all subaddresses derivable from the master keypair
    // 2. mweb(master_scan, master_spend, address_idx) - A single stealth subaddress derived from the master keypair with index 'address_idx'
    // 3. mweb(master_scan, subaddr_spend) - A single stealth subaddress derived from a known subaddress spend key
    if (ctx == ParseScriptContext::TOP && Func("mweb", expr)) {
        auto scan_pk_expr = Expr(expr);
        auto master_scan_pk = ParsePubkey(key_exp_index, scan_pk_expr, ctx, out, error);
        if (!master_scan_pk) {
            error = strprintf("mweb(): %s", error);
            return nullptr;
        }

        CKey master_scan_key;
        if (master_scan_pk->IsRange() || !master_scan_pk->GetPrivKey(-1, out, master_scan_key)) {
            error = strprintf("mweb(): private master_scan_key is needed.");
            return nullptr;
        }
        out.keys.erase(master_scan_key.GetPubKey().GetID());
        key_exp_index++;

        if (expr.empty() || !Const(",", expr)) {
            error = strprintf("mweb(): expected ','");
            return nullptr;
        }

        auto spend_pk_expr = Expr(expr);
        auto master_spend_pk = ParsePubkey(key_exp_index, spend_pk_expr, ctx, out, error);
        if (!master_spend_pk) {
            error = strprintf("mweb(): %s", error);
            return nullptr;
        }
        key_exp_index++;

        auto is_ext_key_expression = [](const Span<const char>& key_expr) {
            std::string key_str(key_expr.begin(), key_expr.end());
            if (!key_str.empty() && key_str.front() == '[') {
                size_t close_bracket = key_str.find(']');
                if (close_bracket == std::string::npos) return false;
                key_str = key_str.substr(close_bracket + 1);
            }
            size_t slash_pos = key_str.find('/');
            std::string key_base = key_str.substr(0, slash_pos);
            if (DecodeExtPubKey(key_base).pubkey.IsValid()) return true;
            if (DecodeExtKey(key_base).key.IsValid()) return true;
            return false;
        };

        std::optional<uint32_t> mweb_index;
        MWEBDescriptor::Type mweb_type = MWEBDescriptor::Type::SINGLE_SUBADDR;
        if (!expr.empty()) {
            if (!Const(",", expr)) {
                error = strprintf("mweb(): expected ',', got '%c'", expr[0]);
                return nullptr;
            }

            if (Const("*", expr)) {
                if (!expr.empty()) {
                    error = strprintf("mweb(): expected end after '*', got '%s'", std::string(expr.begin(), expr.end()));
                    return nullptr;
                }
                mweb_type = MWEBDescriptor::Type::RANGE;
            } else {
                uint32_t index;
                if (ParseUInt32(std::string(expr.begin(), expr.end()), &index)) {
                    mweb_index = index;
                    mweb_type = MWEBDescriptor::Type::SINGLE_INDEX;
                } else {
                    error = strprintf("mweb(): expected '*' or index, got '%s'", std::string(expr.begin(), expr.end()));
                    return nullptr;
                }
            }
        } else if (is_ext_key_expression(spend_pk_expr)) {
            mweb_type = MWEBDescriptor::Type::RANGE;
        }

        return std::make_unique<MWEBDescriptor>(std::move(master_scan_pk), std::move(master_spend_pk), std::move(master_scan_key), mweb_type, mweb_index);
    } else if (Func("mweb", expr)) {
        error = "Can only have mweb() at top level";
        return nullptr;
    }
    if (ctx == ParseScriptContext::TOP && Func("sh", expr)) {
        auto desc = ParseScript(key_exp_index, expr, ParseScriptContext::P2SH, out, error);
        if (!desc || expr.size()) return nullptr;
        return std::make_unique<SHDescriptor>(std::move(desc));
    } else if (Func("sh", expr)) {
        error = "Can only have sh() at top level";
        return nullptr;
    }
    if ((ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH) && Func("wsh", expr)) {
        auto desc = ParseScript(key_exp_index, expr, ParseScriptContext::P2WSH, out, error);
        if (!desc || expr.size()) return nullptr;
        return std::make_unique<WSHDescriptor>(std::move(desc));
    } else if (Func("wsh", expr)) {
        error = "Can only have wsh() at top level or inside sh()";
        return nullptr;
    }
    if (ctx == ParseScriptContext::TOP && Func("addr", expr)) {
        CTxDestination dest = DecodeDestination(std::string(expr.begin(), expr.end()));
        if (!IsValidDestination(dest)) {
            error = "Address is not valid";
            return nullptr;
        }
        return std::make_unique<AddressDescriptor>(std::move(dest));
    } else if (Func("addr", expr)) {
        error = "Can only have addr() at top level";
        return nullptr;
    }
    if (ctx == ParseScriptContext::TOP && Func("tr", expr)) {
        auto arg = Expr(expr);
        auto internal_key = ParsePubkey(key_exp_index, arg, ParseScriptContext::P2TR, out, error);
        if (!internal_key) {
            error = strprintf("tr(): %s", error);
            return nullptr;
        }
        ++key_exp_index;
        std::vector<std::unique_ptr<DescriptorImpl>> subscripts; //!< list of script subexpressions
        std::vector<int> depths; //!< depth in the tree of each subexpression (same length subscripts)
        if (expr.size()) {
            if (!Const(",", expr)) {
                error = strprintf("tr: expected ',', got '%c'", expr[0]);
                return nullptr;
            }
            /** The path from the top of the tree to what we're currently processing.
             * branches[i] == false: left branch in the i'th step from the top; true: right branch.
             */
            std::vector<bool> branches;
            // Loop over all provided scripts. In every iteration exactly one script will be processed.
            // Use a do-loop because inside this if-branch we expect at least one script.
            do {
                // First process all open braces.
                while (Const("{", expr)) {
                    branches.push_back(false); // new left branch
                    if (branches.size() > TAPROOT_CONTROL_MAX_NODE_COUNT) {
                        error = strprintf("tr() supports at most %i nesting levels", TAPROOT_CONTROL_MAX_NODE_COUNT);
                        return nullptr;
                    }
                }
                // Process the actual script expression.
                auto sarg = Expr(expr);
                subscripts.emplace_back(ParseScript(key_exp_index, sarg, ParseScriptContext::P2TR, out, error));
                if (!subscripts.back()) return nullptr;
                depths.push_back(branches.size());
                // Process closing braces; one is expected for every right branch we were in.
                while (branches.size() && branches.back()) {
                    if (!Const("}", expr)) {
                        error = strprintf("tr(): expected '}' after script expression");
                        return nullptr;
                    }
                    branches.pop_back(); // move up one level after encountering '}'
                }
                // If after that, we're at the end of a left branch, expect a comma.
                if (branches.size() && !branches.back()) {
                    if (!Const(",", expr)) {
                        error = strprintf("tr(): expected ',' after script expression");
                        return nullptr;
                    }
                    branches.back() = true; // And now we're in a right branch.
                }
            } while (branches.size());
            // After we've explored a whole tree, we must be at the end of the expression.
            if (expr.size()) {
                error = strprintf("tr(): expected ')' after script expression");
                return nullptr;
            }
        }
        assert(TaprootBuilder::ValidDepths(depths));
        return std::make_unique<TRDescriptor>(std::move(internal_key), std::move(subscripts), std::move(depths));
    } else if (Func("tr", expr)) {
        error = "Can only have tr at top level";
        return nullptr;
    }
    if (ctx == ParseScriptContext::TOP && Func("rawtr", expr)) {
        auto arg = Expr(expr);
        if (expr.size()) {
            error = strprintf("rawtr(): only one key expected.");
            return nullptr;
        }
        auto output_key = ParsePubkey(key_exp_index, arg, ParseScriptContext::P2TR, out, error);
        if (!output_key) return nullptr;
        ++key_exp_index;
        return std::make_unique<RawTRDescriptor>(std::move(output_key));
    } else if (Func("rawtr", expr)) {
        error = "Can only have rawtr at top level";
        return nullptr;
    }
    if (ctx == ParseScriptContext::TOP && Func("raw", expr)) {
        std::string str(expr.begin(), expr.end());
        if (!IsHex(str)) {
            error = "Raw script is not hex";
            return nullptr;
        }
        auto bytes = ParseHex(str);
        return std::make_unique<RawDescriptor>(CScript(bytes.begin(), bytes.end()));
    } else if (Func("raw", expr)) {
        error = "Can only have raw() at top level";
        return nullptr;
    }
    // Process miniscript expressions.
    {
        KeyParser parser(&out, nullptr);
        auto node = miniscript::FromString(std::string(expr.begin(), expr.end()), parser);
        if (node) {
            if (ctx != ParseScriptContext::P2WSH) {
                error = "Miniscript expressions can only be used in wsh";
                return nullptr;
            }
            if (parser.m_key_parsing_error != "") {
                error = std::move(parser.m_key_parsing_error);
                return nullptr;
            }
            if (!node->IsSane()) {
                // Try to find the first insane sub for better error reporting.
                auto insane_node = node.get();
                if (const auto sub = node->FindInsaneSub()) insane_node = sub;
                if (const auto str = insane_node->ToString(parser)) error = *str;
                if (!insane_node->IsValid()) {
                    error += " is invalid";
                } else {
                    error += " is not sane";
                    if (!insane_node->IsNonMalleable()) {
                        error += ": malleable witnesses exist";
                    } else if (insane_node == node.get() && !insane_node->NeedsSignature()) {
                        error += ": witnesses without signature exist";
                    } else if (!insane_node->CheckTimeLocksMix()) {
                        error += ": contains mixes of timelocks expressed in blocks and seconds";
                    } else if (!insane_node->CheckDuplicateKey()) {
                        error += ": contains duplicate public keys";
                    } else if (!insane_node->ValidSatisfactions()) {
                        error += ": needs witnesses that may exceed resource limits";
                    }
                }
                return nullptr;
            }
            return std::make_unique<MiniscriptDescriptor>(std::move(parser.m_keys), std::move(node));
        }
    }
    if (ctx == ParseScriptContext::P2SH) {
        error = "A function is needed within P2SH";
        return nullptr;
    } else if (ctx == ParseScriptContext::P2WSH) {
        error = "A function is needed within P2WSH";
        return nullptr;
    }
    error = strprintf("'%s' is not a valid descriptor function", std::string(expr.begin(), expr.end()));
    return nullptr;
}

std::unique_ptr<DescriptorImpl> InferMultiA(const CScript& script, ParseScriptContext ctx, const SigningProvider& provider)
{
    auto match = MatchMultiA(script);
    if (!match) return {};
    std::vector<std::unique_ptr<PubkeyProvider>> keys;
    keys.reserve(match->second.size());
    for (const auto keyspan : match->second) {
        if (keyspan.size() != 32) return {};
        auto key = InferXOnlyPubkey(XOnlyPubKey{keyspan}, ctx, provider);
        if (!key) return {};
        keys.push_back(std::move(key));
    }
    return std::make_unique<MultiADescriptor>(match->first, std::move(keys));
}

std::unique_ptr<DescriptorImpl> InferScript(const CScript& script, ParseScriptContext ctx, const SigningProvider& provider)
{
    if (ctx == ParseScriptContext::P2TR && script.size() == 34 && script[0] == 32 && script[33] == OP_CHECKSIG) {
        XOnlyPubKey key{Span{script}.subspan(1, 32)};
        return std::make_unique<PKDescriptor>(InferXOnlyPubkey(key, ctx, provider), true);
    }

    if (ctx == ParseScriptContext::P2TR) {
        auto ret = InferMultiA(script, ctx, provider);
        if (ret) return ret;
    }

    std::vector<std::vector<unsigned char>> data;
    TxoutType txntype = Solver(script, data);

    if (txntype == TxoutType::PUBKEY && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        CPubKey pubkey(data[0]);
        if (pubkey.IsValid()) {
            return std::make_unique<PKDescriptor>(InferPubkey(pubkey, ctx, provider));
        }
    }
    if (txntype == TxoutType::PUBKEYHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        uint160 hash(data[0]);
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey)) {
            return std::make_unique<PKHDescriptor>(InferPubkey(pubkey, ctx, provider));
        }
    }
    if (txntype == TxoutType::WITNESS_V0_KEYHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        uint160 hash(data[0]);
        CKeyID keyid(hash);
        CPubKey pubkey;
        if (provider.GetPubKey(keyid, pubkey)) {
            return std::make_unique<WPKHDescriptor>(InferPubkey(pubkey, ctx, provider));
        }
    }
    if (txntype == TxoutType::MULTISIG && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH || ctx == ParseScriptContext::P2WSH)) {
        std::vector<std::unique_ptr<PubkeyProvider>> providers;
        for (size_t i = 1; i + 1 < data.size(); ++i) {
            CPubKey pubkey(data[i]);
            providers.push_back(InferPubkey(pubkey, ctx, provider));
        }
        return std::make_unique<MultisigDescriptor>((int)data[0][0], std::move(providers));
    }
    if (txntype == TxoutType::SCRIPTHASH && ctx == ParseScriptContext::TOP) {
        uint160 hash(data[0]);
        CScriptID scriptid(hash);
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2SH, provider);
            if (sub) return std::make_unique<SHDescriptor>(std::move(sub));
        }
    }
    if (txntype == TxoutType::WITNESS_V0_SCRIPTHASH && (ctx == ParseScriptContext::TOP || ctx == ParseScriptContext::P2SH)) {
        CScriptID scriptid;
        CRIPEMD160().Write(data[0].data(), data[0].size()).Finalize(scriptid.begin());
        CScript subscript;
        if (provider.GetCScript(scriptid, subscript)) {
            auto sub = InferScript(subscript, ParseScriptContext::P2WSH, provider);
            if (sub) return std::make_unique<WSHDescriptor>(std::move(sub));
        }
    }
    if (txntype == TxoutType::WITNESS_V1_TAPROOT && ctx == ParseScriptContext::TOP) {
        // Extract x-only pubkey from output.
        XOnlyPubKey pubkey;
        std::copy(data[0].begin(), data[0].end(), pubkey.begin());
        // Request spending data.
        TaprootSpendData tap;
        if (provider.GetTaprootSpendData(pubkey, tap)) {
            // If found, convert it back to tree form.
            auto tree = InferTaprootTree(tap, pubkey);
            if (tree) {
                // If that works, try to infer subdescriptors for all leaves.
                bool ok = true;
                std::vector<std::unique_ptr<DescriptorImpl>> subscripts; //!< list of script subexpressions
                std::vector<int> depths; //!< depth in the tree of each subexpression (same length subscripts)
                for (const auto& [depth, script, leaf_ver] : *tree) {
                    std::unique_ptr<DescriptorImpl> subdesc;
                    if (leaf_ver == TAPROOT_LEAF_TAPSCRIPT) {
                        subdesc = InferScript(script, ParseScriptContext::P2TR, provider);
                    }
                    if (!subdesc) {
                        ok = false;
                        break;
                    } else {
                        subscripts.push_back(std::move(subdesc));
                        depths.push_back(depth);
                    }
                }
                if (ok) {
                    auto key = InferXOnlyPubkey(tap.internal_key, ParseScriptContext::P2TR, provider);
                    return std::make_unique<TRDescriptor>(std::move(key), std::move(subscripts), std::move(depths));
                }
            }
        }
        // If the above doesn't work, construct a rawtr() descriptor with just the encoded x-only pubkey.
        if (pubkey.IsFullyValid()) {
            auto key = InferXOnlyPubkey(pubkey, ParseScriptContext::P2TR, provider);
            if (key) {
                return std::make_unique<RawTRDescriptor>(std::move(key));
            }
        }
    }

    if (ctx == ParseScriptContext::P2WSH) {
        KeyParser parser(nullptr, &provider);
        auto node = miniscript::FromScript(script, parser);
        if (node && node->IsSane()) {
            return std::make_unique<MiniscriptDescriptor>(std::move(parser.m_keys), std::move(node));
        }
    }

    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        if (GetScriptForDestination(dest) == script) {
            return std::make_unique<AddressDescriptor>(std::move(dest));
        }
    }

    return std::make_unique<RawDescriptor>(script);
}

std::unique_ptr<Descriptor> InferMWEBDescriptor(const StealthAddress& mweb_address, const SigningProvider& provider)
{
    auto has_origin = [](const KeyOriginInfo& origin) {
        return !std::all_of(std::begin(origin.fingerprint), std::end(origin.fingerprint), [](unsigned char c) { return c == 0; }) ||
               !origin.hdkeypath.path.empty() ||
               origin.hdkeypath.mweb_index.has_value();
    };

    const CKeyID sub_spend_id = mweb_address.GetSpendPubKey().GetID();

    // 1) Fetch the master scan private key.
    CKey master_scan_key;
    if (!provider.GetMWEBMasterScanKey(master_scan_key)) {
        return std::make_unique<AddressDescriptor>(mweb_address);
    }

    // 2) Pull index from the subaddress spend pubkey's origin (if known).
    KeyOriginInfo sub_spend_origin;
    std::optional<uint32_t> index;
    if (provider.GetKeyOrigin(sub_spend_id, sub_spend_origin) && sub_spend_origin.hdkeypath.mweb_index) {
        index = *sub_spend_origin.hdkeypath.mweb_index;
    }

    // 3) Fetch the master spend public key (and its origin if available).
    CPubKey master_spend_pk;
    KeyOriginInfo spend_master_origin;
    spend_master_origin.clear();
    const bool have_master_spend_pk = provider.GetMWEBMasterSpendPubKey(master_spend_pk, &spend_master_origin);
    KeyOriginInfo* p_spend_origin = have_master_spend_pk && has_origin(spend_master_origin) ? &spend_master_origin : nullptr;

    // 4) Wrap the scan key in a PubkeyProvider, preserving origin if we have it.
    KeyOriginInfo scan_origin;
    scan_origin.clear();
    const bool have_scan_origin = provider.GetKeyOrigin(master_scan_key.GetPubKey().GetID(), scan_origin) && has_origin(scan_origin);
    std::unique_ptr<PubkeyProvider> scan_inner  = std::make_unique<ConstPubkeyProvider>(0, master_scan_key.GetPubKey(), /*xonly=*/false);
    std::unique_ptr<PubkeyProvider> scan_prov  = have_scan_origin
        ? std::make_unique<OriginPubkeyProvider>(0, scan_origin, std::move(scan_inner))
        : std::move(scan_inner);

    // 5) Prefer the master spend + index form when available.
    if (index && have_master_spend_pk && master_spend_pk.IsValid()) {
        std::unique_ptr<PubkeyProvider> spend_inner = std::make_unique<ConstPubkeyProvider>(1, master_spend_pk, /*xonly=*/false);
        std::unique_ptr<PubkeyProvider> spend_prov = p_spend_origin
            ? std::make_unique<OriginPubkeyProvider>(1, *p_spend_origin, std::move(spend_inner))
            : std::move(spend_inner);
        return std::make_unique<MWEBDescriptor>(std::move(scan_prov), std::move(spend_prov), master_scan_key, MWEBDescriptor::Type::SINGLE_INDEX, index);
    }

    // 6) Fall back to a single-subaddress descriptor using the subaddress spend key.
    const CPubKey sub_spend_pk(mweb_address.GetSpendPubKey().vec());
    std::unique_ptr<PubkeyProvider> spend_inner = std::make_unique<ConstPubkeyProvider>(1, sub_spend_pk, /*xonly=*/false);
    std::unique_ptr<PubkeyProvider> spend_prov = provider.GetKeyOrigin(sub_spend_id, sub_spend_origin)
        ? std::make_unique<OriginPubkeyProvider>(1, sub_spend_origin, std::move(spend_inner))
        : std::move(spend_inner);
    return std::make_unique<MWEBDescriptor>(std::move(scan_prov), std::move(spend_prov), master_scan_key, MWEBDescriptor::Type::SINGLE_SUBADDR, std::nullopt);
}

} // namespace

/** Check a descriptor checksum, and update desc to be the checksum-less part. */
bool CheckChecksum(Span<const char>& sp, bool require_checksum, std::string& error, std::string* out_checksum = nullptr)
{
    using namespace spanparsing;

    auto check_split = Split(sp, '#');
    if (check_split.size() > 2) {
        error = "Multiple '#' symbols";
        return false;
    }
    if (check_split.size() == 1 && require_checksum){
        error = "Missing checksum";
        return false;
    }
    if (check_split.size() == 2) {
        if (check_split[1].size() != 8) {
            error = strprintf("Expected 8 character checksum, not %u characters", check_split[1].size());
            return false;
        }
    }
    auto checksum = DescriptorChecksum(check_split[0]);
    if (checksum.empty()) {
        error = "Invalid characters in payload";
        return false;
    }
    if (check_split.size() == 2) {
        if (!std::equal(checksum.begin(), checksum.end(), check_split[1].begin())) {
            error = strprintf("Provided checksum '%s' does not match computed checksum '%s'", std::string(check_split[1].begin(), check_split[1].end()), checksum);
            return false;
        }
    }
    if (out_checksum) *out_checksum = std::move(checksum);
    sp = check_split[0];
    return true;
}

std::unique_ptr<Descriptor> Parse(const std::string& descriptor, FlatSigningProvider& out, std::string& error, bool require_checksum)
{
    Span<const char> sp{descriptor};
    if (!CheckChecksum(sp, require_checksum, error)) return nullptr;
    uint32_t key_exp_index = 0;
    auto ret = ParseScript(key_exp_index, sp, ParseScriptContext::TOP, out, error);
    if (sp.size() == 0 && ret) return std::unique_ptr<Descriptor>(std::move(ret));
    return nullptr;
}

std::string GetDescriptorChecksum(const std::string& descriptor)
{
    std::string ret;
    std::string error;
    Span<const char> sp{descriptor};
    if (!CheckChecksum(sp, false, error, &ret)) return "";
    return ret;
}

std::unique_ptr<Descriptor> InferDescriptor(const GenericAddress& dest_addr, const SigningProvider& provider)
{
    if (dest_addr.IsMWEB()) {
        return InferMWEBDescriptor(dest_addr.GetMWEBAddress(), provider);
    }

    return InferScript(dest_addr.GetScript(), ParseScriptContext::TOP, provider);
}

void DescriptorCache::CacheParentExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub)
{
    m_parent_xpubs[key_exp_pos] = xpub;
}

void DescriptorCache::CacheDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, const CExtPubKey& xpub)
{
    auto& xpubs = m_derived_xpubs[key_exp_pos];
    xpubs[der_index] = xpub;
}

void DescriptorCache::CacheLastHardenedExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub)
{
    m_last_hardened_xpubs[key_exp_pos] = xpub;
}

bool DescriptorCache::GetCachedParentExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const
{
    const auto& it = m_parent_xpubs.find(key_exp_pos);
    if (it == m_parent_xpubs.end()) return false;
    xpub = it->second;
    return true;
}

bool DescriptorCache::GetCachedDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, CExtPubKey& xpub) const
{
    const auto& key_exp_it = m_derived_xpubs.find(key_exp_pos);
    if (key_exp_it == m_derived_xpubs.end()) return false;
    const auto& der_it = key_exp_it->second.find(der_index);
    if (der_it == key_exp_it->second.end()) return false;
    xpub = der_it->second;
    return true;
}

bool DescriptorCache::GetCachedLastHardenedExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const
{
    const auto& it = m_last_hardened_xpubs.find(key_exp_pos);
    if (it == m_last_hardened_xpubs.end()) return false;
    xpub = it->second;
    return true;
}

void DescriptorCache::CacheMWEBAddress(const uint32_t mweb_index, const StealthAddress& address)
{
    m_addresses[mweb_index] = address;
}

bool DescriptorCache::GetCachedMWEBAddress(const uint32_t mweb_index, StealthAddress& address) const
{
    const auto& it = m_addresses.find(mweb_index);
    if (it == m_addresses.end()) return false;
    address = it->second;
    return true;
}

DescriptorCache DescriptorCache::MergeAndDiff(const DescriptorCache& other)
{
    DescriptorCache diff;
    for (const auto& parent_xpub_pair : other.GetCachedParentExtPubKeys()) {
        CExtPubKey xpub;
        if (GetCachedParentExtPubKey(parent_xpub_pair.first, xpub)) {
            if (xpub != parent_xpub_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached parent xpub does not match already cached parent xpub");
            }
            continue;
        }
        CacheParentExtPubKey(parent_xpub_pair.first, parent_xpub_pair.second);
        diff.CacheParentExtPubKey(parent_xpub_pair.first, parent_xpub_pair.second);
    }
    for (const auto& derived_xpub_map_pair : other.GetCachedDerivedExtPubKeys()) {
        for (const auto& derived_xpub_pair : derived_xpub_map_pair.second) {
            CExtPubKey xpub;
            if (GetCachedDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, xpub)) {
                if (xpub != derived_xpub_pair.second) {
                    throw std::runtime_error(std::string(__func__) + ": New cached derived xpub does not match already cached derived xpub");
                }
                continue;
            }
            CacheDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, derived_xpub_pair.second);
            diff.CacheDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, derived_xpub_pair.second);
        }
    }
    for (const auto& lh_xpub_pair : other.GetCachedLastHardenedExtPubKeys()) {
        CExtPubKey xpub;
        if (GetCachedLastHardenedExtPubKey(lh_xpub_pair.first, xpub)) {
            if (xpub != lh_xpub_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached last hardened xpub does not match already cached last hardened xpub");
            }
            continue;
        }
        CacheLastHardenedExtPubKey(lh_xpub_pair.first, lh_xpub_pair.second);
        diff.CacheLastHardenedExtPubKey(lh_xpub_pair.first, lh_xpub_pair.second);
    }
    for (const auto& address_pos_pair : other.GetCachedMWEBAddresses()) {
        StealthAddress address;
        if (GetCachedMWEBAddress(address_pos_pair.first, address)) {
            if (address != address_pos_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached MWEB address does not match already cached MWEB address");
            }
            continue;
        }
        CacheMWEBAddress(address_pos_pair.first, address_pos_pair.second);
        diff.CacheMWEBAddress(address_pos_pair.first, address_pos_pair.second);
    }
    return diff;
}

const ExtPubKeyMap DescriptorCache::GetCachedParentExtPubKeys() const
{
    return m_parent_xpubs;
}

const std::unordered_map<uint32_t, ExtPubKeyMap> DescriptorCache::GetCachedDerivedExtPubKeys() const
{
    return m_derived_xpubs;
}

const ExtPubKeyMap DescriptorCache::GetCachedLastHardenedExtPubKeys() const
{
    return m_last_hardened_xpubs;
}
