// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "clientversion.h"
#include "init.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "validation.h"
#ifdef ENABLE_WALLET
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#include <stdint.h>

#include <univalue.h>

using namespace std;

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
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total animecoin balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
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
    obj.pushKV("version", CLIENT_VERSION);
    obj.pushKV("protocolversion", PROTOCOL_VERSION);
#ifdef ENABLE_WALLET
    if (pwallet) {
        obj.pushKV("walletversion", pwallet->GetVersion());
        obj.pushKV("balance",       ValueFromAmount(pwallet->GetBalance()));
    }
#endif
    obj.pushKV("blocks",        (int)chainActive.Height());
    obj.pushKV("timeoffset",    GetTimeOffset());
    if(g_connman)
        obj.pushKV("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL));
    obj.pushKV("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string()));
    obj.pushKV("difficulty",    (double)GetDifficulty());
    obj.pushKV("testnet",       Params().TestnetToBeDeprecatedFieldRPC());
#ifdef ENABLE_WALLET
    if (pwallet) {
        obj.pushKV("keypoololdest", pwallet->GetOldestKeyPoolTime());
        obj.pushKV("keypoolsize",   (int)pwallet->GetKeyPoolSize());
    }
    if (pwallet && pwallet->IsCrypted()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK()));
#endif
    obj.pushKV("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    obj.pushKV("errors",        GetWarnings("statusbar"));
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
        obj.pushKV("isscript", false);
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
            obj.pushKV("iscompressed", vchPubKey.IsCompressed());
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        CScript subscript;
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.pushKV("script", GetTxnOutputType(whichType));
            obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));
            UniValue a(UniValue::VARR);
            for (const CTxDestination& addr : addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.pushKV("addresses", a);
            if (whichType == TX_MULTISIG || whichType == TX_MULTISIG_CLTV1)
                obj.pushKV("sigsrequired", nRequired);
        }
        return obj;
    }
};
#endif

UniValue validateaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "validateaddress \"address\"\n"
            "\nReturn information about the given animecoin address.\n"
            "\nArguments:\n"
            "1. \"address\"     (string, required) The animecoin address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"address\", (string) The animecoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,          (boolean) If the address is yours or not\n"
            "  \"isscript\" : true|false,        (boolean) If the key is a script\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,    (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) The account associated with the address, \"\" is the default account\n"
            "  \"timestamp\" : timestamp,        (number, optional) The creation time of the key if available in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\"")
            + HelpExampleRpc("validateaddress", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\"")
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
    ret.pushKV("isvalid", isValid);
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

#ifdef ENABLE_WALLET
        isminetype mine = pwallet ? IsMine(*pwallet, dest) : ISMINE_NO;
        ret.pushKV("ismine", (mine & ISMINE_SPENDABLE) ? true : false);
        ret.pushKV("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false);
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(pwallet), dest);
        ret.pushKVs(detail);
        if (pwallet && pwallet->mapAddressBook.count(dest)) {
            ret.pushKV("account", pwallet->mapAddressBook[dest].name);
        }
        CKeyID keyID;
        if (pwallet) {
            const auto& meta = pwallet->mapKeyMetadata;
            auto it = address.GetKeyID(keyID) ? meta.find(keyID) : meta.end();
            if (it == meta.end()) {
                it = meta.find(CScriptID(scriptPubKey));
            }
            if (it != meta.end()) {
                ret.pushKV("timestamp", it->second.nCreateTime);
                if (!it->second.hdKeypath.empty()) {
                    ret.pushKV("hdkeypath", it->second.hdKeypath);
                    ret.pushKV("hdmasterkeyid", it->second.hdMasterKeyID.GetHex());
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
CScript _createmultisig_redeemScript(CWallet* const pwallet, const UniValue& params, const UniValue& options)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    int64_t cltv_height = 0, cltv_time = 0;
    if (!options.isNull()) {
        std::vector<std::string> keys = options.getKeys();
        for (const std::string& key : keys) {
            const UniValue& val = options[key];
            if (key == "cltv_height" && val.isNum()) {
                cltv_height = val.get_int64();
            } else
            if (key == "cltv_time" && val.isNum()) {
                cltv_time = val.get_int64();
            } else {
                throw runtime_error(strprintf("unknown key/type for option '%s'", key));
            }
        }
    }

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
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
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks));
            CPubKey vchPubKey;
            if (!pwallet->GetPubKey(keyID, vchPubKey)) {
                throw runtime_error(
                    strprintf("no full public key for address %s",ks));
            }
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result;
    if ((cltv_height==0)&&(cltv_time==0))
        result = GetScriptForMultisig(nRequired, pubkeys);
    else
        result = GetScriptForCLTV(nRequired, pubkeys, cltv_height, cltv_time);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));
    return result;
}

UniValue createmultisig(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
#else
    CWallet* const pwallet = nullptr;
#endif

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        string msg = "createmultisig nrequired [\"key\",...] ( { options } )\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are animecoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) animecoin address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"
            "3. options        (object, optional)\n"
            "   {\n"
            "     \"cltv_height\"  (numeric, optional) Minimum block height before received funds can be spent\n"
            "     \"cltv_time\"    (numeric, optional) Minimum approximate time before received funds can be spent (WARNING: This version of " PACKAGE_NAME " does not support spending time-locked coins)\n"
            "   }\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\",\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\\\",\\\"Ad9gq1rYvKDiFWCQPnrXVBCZEhwmQYXNks\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    UniValue options;
    if (request.params.size() > 2) {
        options = request.params[2];
    }
    CScript inner = _createmultisig_redeemScript(pwallet, request.params, options);
    CScriptID innerID(inner);
    CBitcoinAddress address(innerID);
    LogPrintf("%s %s \n", innerID.ToString(), address.ToString());
    UniValue result(UniValue::VOBJ);
    result.pushKV("address", address.ToString());
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));

    return result;
}

UniValue verifymessage(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
            "verifymessage \"address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The animecoin address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    string strAddress  = request.params[0].get_str();
    string strSign     = request.params[1].get_str();
    string strMessage  = request.params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

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
        throw runtime_error(
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
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    string strPrivkey = request.params[0].get_str();
    string strMessage = request.params[1].get_str();

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

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

UniValue setmocktime(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw runtime_error("setmocktime for regression testing (-regtest mode) only");

    // cs_vNodes is locked and node send/receive times are updated
    // atomically with the time change to prevent peers from being
    // disconnected because we think we haven't communicated with them
    // in a long time.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    uint64_t t = GetTime();
    if(g_connman) {
        g_connman->ForEachNode([t](CNode* pnode) {
            pnode->nLastSend = pnode->nLastRecv = t;
        });
    }

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getmemoryinfo\n"
            "Returns an object containing information about memory usage.\n"
            "\nResult:\n"
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
            "\nExamples:\n"
            + HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
        );
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("locked", RPCLockedMemoryInfo());
    return obj;
}

UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw runtime_error(
            "echo|echojson \"message\" ...\n"
            "\nSimply echo back the input arguments. This command is for testing.\n"
            "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in"
            "bitcoin-cli and the GUI. There is no server-side difference."
        );

    return request.params;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
  { "control",            "getinfo",                &getinfo,                true,  {} }, /* uses wallet if enabled */
  { "control",            "getmemoryinfo",          &getmemoryinfo,          true,  {} },
  { "util",               "validateaddress",        &validateaddress,        true,  {"address"} }, /* uses wallet if enabled */
  { "util",               "createmultisig",         &createmultisig,         true,  {"nrequired","keys","options"} },
  { "util",               "verifymessage",          &verifymessage,          true,  {"address","signature","message"} },
  { "util",               "signmessagewithprivkey", &signmessagewithprivkey, true,  {"privkey","message"} },

    /* Not shown in help */
  { "hidden",             "setmocktime",            &setmocktime,            true,  {"timestamp"}},
  { "hidden",             "echo",                   &echo,                   true,  {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
  { "hidden",             "echojson",               &echo,                  true,  {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
};

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
