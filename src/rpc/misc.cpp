// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chain.h"
#include "clientversion.h"
#include "core_io.h"
#include "init.h"
#include "validation.h"
#include "httpserver.h"
#include "net.h"
#include "netbase.h"
#include "rpc/blockchain.h"
#include "rpc/server.h"
#include "timedata.h"
#include "txdb.h"
#include "util.h"
#include "utilstrencodings.h"
#ifdef ENABLE_WALLET
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include "warnings.h"

#include "addressindex.h"

#include <stdint.h>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <boost/thread/thread.hpp> // boost::thread::interrupt
#include <univalue.h>

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getinfo\n"
            "\nDEPRECATED. Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"deprecation-warning\": \"...\" (string) warning that the getinfo command is deprecated and will be removed in 0.16\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total litecoin balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",       (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"             (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("deprecation-warning", "WARNING: getinfo is deprecated and will be fully removed in 0.16."
        " Projects should transition to using getblockchaininfo, getnetworkinfo, and getwalletinfo before upgrading to 0.16"));
    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwallet) {
        obj.push_back(Pair("walletversion", pwallet->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(pwallet->GetBalance())));
    }
#endif
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    if(g_connman)
        obj.push_back(Pair("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL)));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string())));
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    obj.push_back(Pair("testnet",       Params().NetworkIDString() == CBaseChainParams::TESTNET));
#ifdef ENABLE_WALLET
    if (pwallet) {
        obj.push_back(Pair("keypoololdest", pwallet->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwallet->GetKeyPoolSize()));
    }
    if (pwallet && pwallet->IsCrypted()) {
        obj.push_back(Pair("unlocked_until", pwallet->nRelockTime));
    }
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
#endif
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    DescribeAddressVisitor(CWallet *_pwallet) : pwallet(_pwallet) {}

    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            UniValue a(UniValue::VARR);
            for (const CTxDestination& addr : addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};
#endif

UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given litecoin address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The litecoin address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\", (string) The litecoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"script\" : \"type\"             (string, optional) The output script type. Possible types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash, witness_v0_scripthash\n"
            "  \"hex\" : \"hex\",                (string, optional) The redeemscript for the p2sh address\n"
            "  \"addresses\"                   (string, optional) Array of addresses associated with the known redeemscript\n"
            "    [\n"
            "      \"address\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"sigsrequired\" : xxxxx        (numeric, optional) Number of signatures required to spend multisig output\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "  \"timestamp\" : timestamp,        (number, optional) The creation time of the key if available in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"LER4HnAEFwYHbmGxCfP2po1nPrUeiK8KM2\"")
            + HelpExampleRpc("validateaddress", "\"LER4HnAEFwYHbmGxCfP2po1nPrUeiK8KM2\"")
        );

#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    LOCK2(cs_main, pwallet ? &pwallet->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    CBitcoinAddress address(request.params[0].get_str());
    bool isValid = address.IsValid();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        std::string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwallet ? IsMine(*pwallet, dest) : ISMINE_NO;
        ret.push_back(Pair("ismine", bool(mine & ISMINE_SPENDABLE)));
        ret.push_back(Pair("iswatchonly", bool(mine & ISMINE_WATCH_ONLY)));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(pwallet), dest);
        ret.pushKVs(detail);
        if (pwallet && pwallet->mapAddressBook.count(dest)) {
            ret.push_back(Pair("account", pwallet->mapAddressBook[dest].name));
        }
        CKeyID keyID;
        if (pwallet) {
            const auto& meta = pwallet->mapKeyMetadata;
            auto it = address.GetKeyID(keyID) ? meta.find(keyID) : meta.end();
            if (it == meta.end()) {
                it = meta.find(CScriptID(scriptPubKey));
            }
            if (it != meta.end()) {
                ret.push_back(Pair("timestamp", it->second.nCreateTime));
                if (!it->second.hdKeypath.empty()) {
                    ret.push_back(Pair("hdkeypath", it->second.hdKeypath));
                    ret.push_back(Pair("hdmasterkeyid", it->second.hdMasterKeyID.GetHex()));
                }
            }
        }
#endif
    }
    return ret;
}

// Needed even with !ENABLE_WALLET, to pass (ignored) pointers around
class CWallet;

/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(CWallet * const pwallet, const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw std::runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw std::runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw std::runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (pwallet && address.IsValid()) {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw std::runtime_error(
                    strprintf("%s does not refer to a key",ks));
            CPubKey vchPubKey;
            if (!pwallet->GetPubKey(keyID, vchPubKey)) {
                throw std::runtime_error(
                    strprintf("no full public key for address %s",ks));
            }
            if (!vchPubKey.IsFullyValid())
                throw std::runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw std::runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw std::runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw std::runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

UniValue createmultisig(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
#else
    CWallet * const pwallet = nullptr;
#endif

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 2)
    {
        std::string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are litecoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) litecoin address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"LEr4hnAefwYhBmGxcFP2Po1NPrUEIk8KM2\\\",\\\"LYKr1oaPSqShthukmLDhdZsqUJgzVnQiAQ\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"LEr4hnAefwYhBmGxcFP2Po1NPrUEIk8KM2\\\",\\\"LYKr1oaPSqShthukmLDhdZsqUJgzVnQiAQ\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(pwallet, request.params);
    CScriptID innerID(inner);
    CBitcoinAddress address(innerID);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The litecoin address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"LEr4hNAefWYhBMgxCFP2Po1NPrUeiK8kM2\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"LEr4hNAefWYhBMgxCFP2Po1NPrUeiK8kM2\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"LEr4hNAefWYhBMgxCFP2Po1NPrUeiK8kM2\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}

UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessagewithprivkey \"privkey\" \"message\"\n"
            "\nSign a message with the private key of an address\n"
            "\nArguments:\n"
            "1. \"privkey\"         (string, required) The private key to sign the message with.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"LEr4hNAefWYhBMgxCFP2Po1NPrUeiK8kM2\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strPrivkey);
    if (!fGood)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    CKey key = vchSecret.GetKey();
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw std::runtime_error("setmocktime for regression testing (-regtest mode) only");

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("used", uint64_t(stats.used)));
    obj.push_back(Pair("free", uint64_t(stats.free)));
    obj.push_back(Pair("total", uint64_t(stats.total)));
    obj.push_back(Pair("locked", uint64_t(stats.locked)));
    obj.push_back(Pair("chunks_used", uint64_t(stats.chunks_used)));
    obj.push_back(Pair("chunks_free", uint64_t(stats.chunks_free)));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getmemoryinfo (\"mode\")\n"
            "Returns an object containing information about memory usage.\n"
            "Arguments:\n"
            "1. \"mode\" determines what kind of information is returned. This argument is optional, the default mode is \"stats\".\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+).\n"
            "\nResult (mode \"stats\"):\n"
            "{\n"
            "  \"locked\": {               (json object) Information about locked memory manager\n"
            "    \"used\": xxxxx,          (numeric) Number of bytes used\n"
            "    \"free\": xxxxx,          (numeric) Number of bytes available in current arenas\n"
            "    \"total\": xxxxxxx,       (numeric) Total number of bytes managed\n"
            "    \"locked\": xxxxxx,       (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n"
            "    \"chunks_used\": xxxxx,   (numeric) Number allocated chunks\n"
            "    \"chunks_free\": xxxxx,   (numeric) Number unused chunks\n"
            "  }\n"
            "}\n"
            "\nResult (mode \"mallocinfo\"):\n"
            "\"<malloc version=\"1\">...\"\n"
            "\nExamples:\n"
            + HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
        );

    std::string mode = (request.params.size() < 1 || request.params[0].isNull()) ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("locked", RPCLockedMemoryInfo()));
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

uint32_t getCategoryMask(UniValue cats) {
    cats = cats.get_array();
    uint32_t mask = 0;
    for (unsigned int i = 0; i < cats.size(); ++i) {
        uint32_t flag = 0;
        std::string cat = cats[i].get_str();
        if (!GetLogCategory(&flag, &cat)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
        mask |= flag;
    }
    return mask;
}

UniValue logging(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "logging [include,...] <exclude>\n"
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories that are currently being debug logged.\n"
            "When called with arguments, adds or removes categories from debug logging.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "libevent logging is configured on startup and cannot be modified by this RPC during runtime."
            "Arguments:\n"
            "1. \"include\" (array of strings) add debug logging for these categories.\n"
            "2. \"exclude\" (array of strings) remove debug logging for these categories.\n"
            "\nResult: <categories>  (string): a list of the logging categories that are active.\n"
            "\nExamples:\n"
            + HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], \"[libevent]\"")
        );
    }

    uint32_t originalLogCategories = logCategories;
    if (request.params.size() > 0 && request.params[0].isArray()) {
        logCategories |= getCategoryMask(request.params[0]);
    }

    if (request.params.size() > 1 && request.params[1].isArray()) {
        logCategories &= ~getCategoryMask(request.params[1]);
    }

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    uint32_t changedLogCategories = originalLogCategories ^ logCategories;
    if (changedLogCategories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(logCategories & BCLog::LIBEVENT)) {
            logCategories &= ~BCLog::LIBEVENT;
            if (changedLogCategories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            "echo|echojson \"message\" ...\n"
            "\nSimply echo back the input arguments. This command is for testing.\n"
            "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in"
            "litecoin-cli and the GUI. There is no server-side difference."
        );

    return request.params;
}

static CAddressUnspentKey AddToUnspentIndex(const uint256& txid, const CTxOut &out, uint32_t nOut, std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >& addressUnspentIndex, const CAddressUnspentValue &unspent)
{
    if (out.scriptPubKey.IsPayToScriptHash()) {
        std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);
        CAddressUnspentKey key(2, uint160(hashBytes), txid, nOut);
        addressUnspentIndex.push_back(std::make_pair(key, unspent));
        return key;
    } else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
        std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
        CAddressUnspentKey key(1, uint160(hashBytes), txid, nOut);
        addressUnspentIndex.push_back(std::make_pair(key, unspent));
        return key;
    }
    // what about IsPayToWitnessScriptHash?
    return CAddressUnspentKey();
}

static void ProcessOutputs(const uint256& txid, const std::map<uint32_t, Coin>& outputs, std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >& addressUnspentIndex, CAddressUnspentKey &maxKey)
{
    assert(!outputs.empty());
    for (const auto output : outputs) {
        if (output.second.nHeight < nAddressIndexFromHeight) {
            continue;
        }
        const CTxOut& out = output.second.out;
        CAddressUnspentKey lastKey;
        if (fAddressIndex) {
            lastKey = AddToUnspentIndex(txid, out, output.first, addressUnspentIndex, CAddressUnspentValue(out.nValue, out.scriptPubKey, output.second.nHeight));
        } else {
            lastKey = AddToUnspentIndex(txid, out, output.first, addressUnspentIndex, CAddressUnspentValue());
            // TODO the comparison needs to be correct (same way as leveldb orders those keys)
            if (maxKey < lastKey) {
                maxKey.type = lastKey.type;
                // very bad performance-wise, need to optimize!
                maxKey.hashBytes.SetHex(lastKey.hashBytes.GetHex());
                maxKey.txhash.SetHex(lastKey.txhash.GetHex());
                maxKey.index = lastKey.index;
            }
        }
    }
}

static int ManageOptionalIndices(CCoinsView *view)
{    
    // build/erase index: prepare the addressUnspentIndex vector
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    CAddressUnspentKey maxkey;
    int count = 0;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ProcessOutputs(prevkey, outputs, addressUnspentIndex, maxkey);
                outputs.clear();
                if (addressUnspentIndex.size() > 8192 && !UpdateOptionalIndices(addressUnspentIndex)) {
                    error("%s: failed to write address unspent index", __func__);
                    return -1;
                }
                count += addressUnspentIndex.size();
                addressUnspentIndex.clear();
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
        } else {
            error("%s: unable to read value", __func__);
            return -1;
        }
        pcursor->Next();
    }
    if (!outputs.empty()) {
        ProcessOutputs(prevkey, outputs, addressUnspentIndex, maxkey);
    }
    if (!UpdateOptionalIndices(addressUnspentIndex)) {
        error("%s: failed to write address unspent index", __func__);
        return -1;
    }
    count += addressUnspentIndex.size();
    if (!fAddressIndex) {
        // flag is changed to false, compact range starting from empty CAddressUnspentKey()
        // and ending the max key found after all ProcessOutputs calls
        CompactOptionalIndices(const_cast<const CAddressUnspentKey&>(maxkey));
    }
    return count;
}

UniValue indexDescription(int count)
{
    UniValue ret(UniValue::VOBJ);
    UniValue indexDesc(UniValue::VOBJ);
    indexDesc.push_back(Pair("enabled", fAddressIndex));
    if (fAddressIndex) indexDesc.push_back(Pair("fromHeight", nAddressIndexFromHeight));
    if (count >= 0) indexDesc.push_back(Pair("records", count));
    ret.push_back(Pair("addressUnspent", indexDesc));
    return ret;
}

UniValue indexchainstate(const JSONRPCRequest& request)
{
    UniValue params = request.params;
    if (request.fHelp || params.size() > 1)
        throw std::runtime_error(
            "indexchainstate ( indexconfig )\n"
            "\nEnables or disables optional indices.\n"
            "Without params, returns enabled/disabled state for each index and additional index settings like fromHeight (if any).\n"
            "Enabling may take a while, and blocks will not be connected/disconnected while this index is being built.\n"
            "\nExamples:\n"
            + HelpExampleCli("indexchainstate", "'{\"addressUnspent\":{\"enable\":true,\"fromHeight\":1000000}}'")
            + HelpExampleRpc("indexchainstate", "{\"addressUnspent\":{\"enable\":true,\"fromHeight\":1000000}}")
        );

    // re-read flag just in case we are called too early...
    pblocktree->ReadFlag(indexChainstate + indexAddressUnspent, fAddressIndex);
    if (params.size() == 0) {
        if (fAddressIndex && !pblocktree->ReadNumericSetting(indexChainstate + indexAddressUnspent + settingFromHeight, nAddressIndexFromHeight))
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("%s flag was set without %s setting", indexChainstate + indexAddressUnspent, indexChainstate + indexAddressUnspent + settingFromHeight));
        return indexDescription(-1);
    }
    if (!params[0].isObject())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "indexconfig: object expected");
    UniValue addressUnspentConf = find_value(params[0].get_obj(), "addressUnspent");
    if (!addressUnspentConf.isObject())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Currently supported indices: addressUnspent");
    UniValue enable = find_value(addressUnspentConf, "enable");
    if (!enable.isBool())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "indexconfig.addressUnspent.enable: boolean expected");
    UniValue fromHeight = find_value(addressUnspentConf, "fromHeight");
    int fromHeightNew = 0;
    if (!fromHeight.isNull()) {
        if (!fromHeight.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "indexconfig.addressUnspent.fromHeight: number expected");
        fromHeightNew = fromHeight.get_int();
    }

    pblocktree->ReadNumericSetting(indexChainstate + indexAddressUnspent + settingFromHeight, nAddressIndexFromHeight);
    if ((fAddressIndex && enable.get_bool() && nAddressIndexFromHeight == fromHeightNew) || (!fAddressIndex && !enable.get_bool())) {
        // Nothing to do, return immediately
        return indexDescription(-1);
    } else if (fAddressIndex && !enable.get_bool()) {
        // Clear index
        LOCK(cs_main);
        pblocktree->WriteFlag(indexChainstate + indexAddressUnspent, false);
        fAddressIndex = false;
        pblocktree->WriteNumericSetting(indexChainstate + indexAddressUnspent + settingFromHeight, 0);
        // provide a way to clear data from specific height as well, just in case:
        nAddressIndexFromHeight = fromHeightNew > 0 ? fromHeightNew : nAddressIndexFromHeight;
        if (ManageOptionalIndices(pcoinsdbview) < 0) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to erase optional index");
        }
        LogPrintf("%s: address unspent index disabled\n", __func__);
        return indexDescription(-1);
    }
    
    LOCK(cs_main);
    // Clear index first if we are rebuilding it with new fromHeight > nAddressIndexFromHeight
    if (fAddressIndex && nAddressIndexFromHeight < fromHeightNew) {
        fAddressIndex = false;
        if (ManageOptionalIndices(pcoinsdbview) < 0) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to erase optional index");
        }
    }
    FlushStateToDisk();
    fAddressIndex = true;
    nAddressIndexFromHeight = fromHeightNew;
    int count = ManageOptionalIndices(pcoinsdbview);
    if (count < 0) {
        fAddressIndex = false;
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set or to write optional index");
    }
    if (!pblocktree->WriteFlag(indexChainstate + indexAddressUnspent, fAddressIndex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("failed to write %s flag", indexChainstate + indexAddressUnspent));
    }
    pblocktree->WriteNumericSetting(indexChainstate + indexAddressUnspent + settingFromHeight, nAddressIndexFromHeight);
    LogPrintf("%s: address unspent index %s with fromHeight=%d\n", __func__, fAddressIndex ? "enabled" : "disabled", nAddressIndexFromHeight);
    return indexDescription(count);
}

bool getAddressFromIndex(const int &type, const uint160 &hash, std::string &address)
{
    if (type == 2) {
        address = CBitcoinAddress(CScriptID(hash)).ToString();
    } else if (type == 1) {
        address = CBitcoinAddress(CKeyID(hash)).ToString();
    } else {
        return false;
    }
    return true;
}

bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint160, int> > &addresses)
{
    if (params[0].isStr()) {
        
        const std::string& strAddress = params[0].get_str();
        if (!strAddress.empty() && strAddress != std::string("json")) {
            CBitcoinAddress address(strAddress);
            uint160 hashBytes;
            int type = 0;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid address %s in params[0]", strAddress));
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    }
    if (params.size() > 1 && params[1].isObject()) {

        UniValue addressValues = find_value(params[1].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {
            const std::string& strAddress = it->get_str();
            CBitcoinAddress address(strAddress);
            uint160 hashBytes;
            int type = 0;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid address %s in params[1]", strAddress));
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    }
    if (addresses.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address(es)");
    }

    return true;
}

bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
    return a.second.blockHeight < b.second.blockHeight;
}

UniValue getaddressutxos(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getaddressutxos \"address\" ( json )\n"
            "\nReturns all unspent outputs for an address or list of addresses (requires \"addressUnspent\" index to be enabled via \"indexchainstate\").\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The base58check encoded address\n"
            "2. json              (object, optional) a json object for more than one address:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ],\n"
            "  \"chainInfo\"  (boolean) Include chain info with results\n"
            "}\n"
            "The \"address\" is always tried to be validated, so in order to specify only the json,\n"
            "provide value \"json\" for parameter 1 (see examples).\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The address base58check encoded\n"
            "    \"txid\"  (string) The output txid\n"
            "    \"height\"  (number) The block height\n"
            "    \"outputIndex\"  (number) The output index\n"
            "    \"script\"  (strin) The script hex encoded\n"
            "    \"satoshis\"  (number) The number of satoshis of the output\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressutxos", "LMgCYZT6dD5kiyKCA1mKSBE5Rnczx9SFif")
            + HelpExampleCli("getaddressutxos", "json '{\"addresses\": [\"LXG2WogdCfVKAGdsLNwi4dbyS3PUwYpaXx\"]}'")
            + HelpExampleRpc("getaddressutxos", "\"LMgCYZT6dD5kiyKCA1mKSBE5Rnczx9SFif\"")
            + HelpExampleRpc("getaddressutxos", "\"json\", {\"addresses\": [\"LXG2WogdCfVKAGdsLNwi4dbyS3PUwYpaXx\"], \"chainInfo\": true}")
            );

    bool includeChainInfo = false;
    if (request.params.size() > 1 && request.params[1].isObject()) {
        UniValue chainInfo = find_value(request.params[1].get_obj(), "chainInfo");
        if (chainInfo.isBool()) {
            includeChainInfo = chainInfo.get_bool();
        }
    }

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(request.params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        // reading the index is done here
        if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Optional chainstate index \"addressUnspent\" needs to be enabled");
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    UniValue utxos(UniValue::VARR);

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        UniValue output(UniValue::VOBJ);
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        output.push_back(Pair("address", address));
        output.push_back(Pair("txid", it->first.txhash.GetHex()));
        output.push_back(Pair("outputIndex", (int)it->first.index));
        output.push_back(Pair("script", HexStr(it->second.script.begin(), it->second.script.end())));
        output.push_back(Pair("satoshis", it->second.satoshis));
        output.push_back(Pair("height", it->second.blockHeight));
        utxos.push_back(output);
    }

    if (includeChainInfo) {
        UniValue result(UniValue::VOBJ);
        result.push_back(Pair("utxos", utxos));

        LOCK(cs_main);
        result.push_back(Pair("hash", chainActive.Tip()->GetBlockHash().GetHex()));
        result.push_back(Pair("height", (int)chainActive.Height()));
        return result;
    } else {
        return utxos;
    }
}


static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getinfo",                &getinfo,                true,  {} }, /* uses wallet if enabled */
    { "control",            "getmemoryinfo",          &getmemoryinfo,          true,  {"mode"} },
    { "util",               "validateaddress",        &validateaddress,        true,  {"address"} }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         true,  {"nrequired","keys"} },
    { "util",               "verifymessage",          &verifymessage,          true,  {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, true,  {"privkey","message"} },

    /* Optional indices */
    { "indices",            "getaddressutxos",        &getaddressutxos,        true,  {"address", "json"} },
    { "indices",            "indexchainstate",        &indexchainstate,        true,  {"indexconfig"} },
    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            true,  {"timestamp"}},
    { "hidden",             "echo",                   &echo,                   true,  {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   true,  {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "logging",                &logging,                true,  {"include", "exclude"}},
};

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
