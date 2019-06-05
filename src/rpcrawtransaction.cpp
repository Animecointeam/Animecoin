// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "keystore.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpcserver.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "uint256.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include "univalue/univalue.h"

using namespace boost;
using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", scriptPubKey.ToString()));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    UniValue vin(UniValue::VARR);
    for (const CTxIn& txin : tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", txin.scriptSig.ToString()));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

UniValue getrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
                "getrawtransaction \"txid\" ( verbose )\n"
                "\nNOTE: By default this function only works sometimes. This is when the tx is in the mempool\n"
                "or there is an unspent output in the utxo for this transaction. To make it always work,\n"
                "you need to maintain a transaction index, using the -txindex command line option.\n"
                "\nReturn the raw transaction data.\n"
                "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
                "If verbose is non-zero, returns an Object with information about 'txid'.\n"

                "\nArguments:\n"
                "1. \"txid\"      (string, required) The transaction id\n"
                "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

                "\nResult (if verbose is not set or set to 0):\n"
                "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

                "\nResult (if verbose > 0):\n"
                "{\n"
                "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
                "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
                "  \"version\" : n,          (numeric) The version\n"
                "  \"locktime\" : ttt,       (numeric) The lock time\n"
                "  \"vin\" : [               (array of json objects)\n"
                "     {\n"
                "       \"txid\": \"id\",    (string) The transaction id\n"
                "       \"vout\": n,         (numeric) \n"
                "       \"scriptSig\": {     (json object) The script\n"
                "         \"asm\": \"asm\",  (string) asm\n"
                "         \"hex\": \"hex\"   (string) hex\n"
                "       },\n"
                "       \"sequence\": n      (numeric) The script sequence number\n"
                "     }\n"
                "     ,...\n"
                "  ],\n"
                "  \"vout\" : [              (array of json objects)\n"
                "     {\n"
                "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
                "       \"n\" : n,                    (numeric) index\n"
                "       \"scriptPubKey\" : {          (json object)\n"
                "         \"asm\" : \"asm\",          (string) the asm\n"
                "         \"hex\" : \"hex\",          (string) the hex\n"
                "         \"reqSigs\" : n,            (numeric) The required sigs\n"
                "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
                "         \"addresses\" : [           (json array of string)\n"
                "           \"animecoinaddress\"          (string) animecoin address\n"
                "           ,...\n"
                "         ]\n"
                "       }\n"
                "     }\n"
                "     ,...\n"
                "  ],\n"
                "  \"blockhash\" : \"hash\",   (string) the block hash\n"
                "  \"confirmations\" : n,      (numeric) The confirmations\n"
                "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
                "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getrawtransaction", "\"mytxid\"")
                + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
                + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
            );

    LOCK(cs_main);

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    string strHex = EncodeHexTx(tx);

    if (!fVerbose)
        return strHex;

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

UniValue createrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...}\n"
                "\nCreate a transaction spending the given inputs and sending to the given addresses.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n"

                "\nArguments:\n"
                "1. \"transactions\"        (string, required) A json array of json objects\n"
                "     [\n"
                "       {\n"
                "         \"txid\":\"id\",  (string, required) The transaction id\n"
                "         \"vout\":n        (numeric, required) The output number\n"
                "       }\n"
                "       ,...\n"
                "     ]\n"
                "2. \"addresses\"           (string, required) a json object with addresses as keys and amounts as values\n"
                "    {\n"
                "      \"address\": x.xxx   (numeric, required) The key is the bitcoin address, the value is the " + CURRENCY_UNIT + " amount\n"
                "      ,...\n"
                "    }\n"

                "\nResult:\n"
                "\"transaction\"            (string) hex string of the transaction\n"

                "\nExamples\n"
                + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
                + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
            );

    LOCK(cs_main);

    RPCTypeCheck(params, {UniValue::VARR, UniValue::VOBJ});

    UniValue inputs = params[0].get_array();
    UniValue sendTo = params[1].get_obj();

    CMutableTransaction rawTx;

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(txid, nOutput));
        rawTx.vin.push_back(in);
    }

    set<CBitcoinAddress> setAddress;
    vector<string> addrList = sendTo.getKeys();
    for (const string& name_ : addrList) {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Animecoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    return EncodeHexTx(rawTx);
}

UniValue decoderawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "decoderawtransaction \"hexstring\"\n"
                "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

                "\nArguments:\n"
                "1. \"hex\"      (string, required) The transaction hex string\n"

                "\nResult:\n"
                "{\n"
                "  \"txid\" : \"id\",        (string) The transaction id\n"
                "  \"version\" : n,          (numeric) The version\n"
                "  \"locktime\" : ttt,       (numeric) The lock time\n"
                "  \"vin\" : [               (array of json objects)\n"
                "     {\n"
                "       \"txid\": \"id\",    (string) The transaction id\n"
                "       \"vout\": n,         (numeric) The output number\n"
                "       \"scriptSig\": {     (json object) The script\n"
                "         \"asm\": \"asm\",  (string) asm\n"
                "         \"hex\": \"hex\"   (string) hex\n"
                "       },\n"
                "       \"sequence\": n     (numeric) The script sequence number\n"
                "     }\n"
                "     ,...\n"
                "  ],\n"
                "  \"vout\" : [             (array of json objects)\n"
                "     {\n"
                "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
                "       \"n\" : n,                    (numeric) index\n"
                "       \"scriptPubKey\" : {          (json object)\n"
                "         \"asm\" : \"asm\",          (string) the asm\n"
                "         \"hex\" : \"hex\",          (string) the hex\n"
                "         \"reqSigs\" : n,            (numeric) The required sigs\n"
                "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
                "         \"addresses\" : [           (json array of string)\n"
                "           \"AGrq2u2iB9AVZqhLVzPvqdJs2X8o41wzHJ\"   (string) animecoin address\n"
                "           ,...\n"
                "         ]\n"
                "       }\n"
                "     }\n"
                "     ,...\n"
                "  ],\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
                + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
            );

    LOCK(cs_main);

    RPCTypeCheck(params, {UniValue::VSTR});

    CTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(tx, uint256(), result);

    return result;
}

UniValue decodescript(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decodescript \"hex\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hex\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) animecoin address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) script address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodescript", "\"hexstring\"")
            + HelpExampleRpc("decodescript", "\"hexstring\"")
        );

    LOCK(cs_main);

    RPCTypeCheck(params, {UniValue::VSTR});

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.push_back(Pair("p2sh", CBitcoinAddress(CScriptID(script)).ToString()));
    return r;
}

UniValue signrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
                "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
                "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
            #ifdef ENABLE_WALLET
                        + HelpRequiringPassphrase() + "\n"
            #endif

                        "\nArguments:\n"
                        "1. \"hexstring\"     (string, required) The transaction hex string\n"
                        "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
                        "     [               (json array of json objects, or 'null' if none provided)\n"
                        "       {\n"
                        "         \"txid\":\"id\",             (string, required) The transaction id\n"
                        "         \"vout\":n,                  (numeric, required) The output number\n"
                        "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
                        "         \"redeemScript\": \"hex\"    (string, required for P2SH) redeem script\n"
                        "       }\n"
                        "       ,...\n"
                        "    ]\n"
                        "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
                        "    [                  (json array of strings, or 'null' if none provided)\n"
                        "      \"privatekey\"   (string) private key in base58-encoding\n"
                        "      ,...\n"
                        "    ]\n"
                        "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
                        "       \"ALL\"\n"
                        "       \"NONE\"\n"
                        "       \"SINGLE\"\n"
                        "       \"ALL|ANYONECANPAY\"\n"
                        "       \"NONE|ANYONECANPAY\"\n"
                        "       \"SINGLE|ANYONECANPAY\"\n"

                        "\nResult:\n"
                        "{\n"
                        "  \"hex\": \"value\",   (string) The raw transaction with signature(s) (hex-encoded string)\n"
                        "  \"complete\": n       (numeric) if transaction has a complete set of signature (0 if not)\n"
                        "}\n"

                        "\nExamples:\n"
                        + HelpExampleCli("signrawtransaction", "\"myhex\"")
                        + HelpExampleRpc("signrawtransaction", "\"myhex\"")
                    );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : nullptr);
#else
    LOCK(cs_main);
#endif

    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VARR, UniValue::VARR, UniValue::VSTR}, true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CMutableTransaction> txVariants;
    while (!ssData.empty()) {
        try {
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (const std::exception&) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && !params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = params[2].get_array();
        for (unsigned int idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && !params[1].isNull()) {
        UniValue prevTxs = params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut, {{"txid", UniValue::VSTR}, {"vout", UniValue::VNUM}, {"scriptPubKey", UniValue::VSTR}});

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + coins->vout[nOut].scriptPubKey.ToString() + "\nvs:\n"+
                        scriptPubKey.ToString();
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut+1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0; // we don't know the actual output value
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                RPCTypeCheckObj(prevOut, {{"txid", UniValue::VSTR}, {"vout", UniValue::VNUM}, {"scriptPubKey", UniValue::VSTR}, {"redeemScript", UniValue::VSTR}});
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && !params[3].isNull()) {
        static map<string, int> mapSigHashValues =
        {
            {string("ALL"), int(SIGHASH_ALL)},
            {string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)},
            {string("NONE"), int(SIGHASH_NONE)},
            {string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY)},
            {string("SINGLE"), int(SIGHASH_SINGLE)},
            {string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)}
        };
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == nullptr || !coins->IsAvailable(txin.prevout.n)) {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        for (const CMutableTransaction& txv : txVariants) {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&mergedTx, i)))
            fComplete = false;
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
    result.push_back(Pair("complete", fComplete));

    return result;
}

UniValue sendrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
                "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
                "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
                "\nAlso see createrawtransaction and signrawtransaction calls.\n"
                "\nArguments:\n"
                "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
                "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
                "\nResult:\n"
                "\"hex\"             (string) The transaction hash in hex\n"
                "\nExamples:\n"
                "\nCreate a transaction\n"
                + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
                "Sign the transaction, and get back the hex\n"
                + HelpExampleCli("signrawtransaction", "\"myhex\"") +
                "\nSend the transaction (signed hex)\n"
                + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
                "\nAs a json rpc call\n"
                + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
            );

    LOCK(cs_main);

    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VBOOL});

    // parse hex string from parameter
    CTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    CCoinsViewCache &view = *pcoinsTip;
    const CCoins* existingCoins = view.AccessCoins(hashTx);
    bool fHaveMempool = mempool.exists(hashTx);
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000;
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        if (!AcceptToMemoryPool(mempool, state, tx, false, nullptr, !fOverrideFees)) {
            if(state.IsInvalid())
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            else
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    RelayTransaction(tx);

    return hashTx.GetHex();
}