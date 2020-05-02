// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "keystore.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/standard.h"
#include "uint256.h"
#include "validation.h"
#include "validationinterface.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <future>
#include <stdint.h>

#include <univalue.h>

using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.pushKV("addresses", a);
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("locktime", (int64_t)tx.nLockTime);
    UniValue vin(UniValue::VARR);
    for (const CTxIn& txin : tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
        else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end()));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        out.pushKV("value", ValueFromAmount(txout.nValue));
        out.pushKV("n", (int64_t)i);
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    if (!hashBlock.IsNull()) {
        entry.pushKV("blockhash", hashBlock.GetHex());
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.pushKV("confirmations", 1 + chainActive.Height() - pindex->nHeight);
                entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            }
            else
                entry.pushKV("confirmations", 0);
        }
    }
}

UniValue getrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw runtime_error(
                "getrawtransaction \"txid\" ( verbose \"blockhash\" )\n"

                "\nNOTE: By default this function only works for mempool transactions. If the -txindex option is\n"
                "enabled, it also works for blockchain transactions. If the block which contains the transaction\n"
                "is known, its hash can be provided even for nodes without -txindex. Note that if a blockhash is\n"
                "provided, only that block will be searched and if the transaction is in the mempool or other\n"
                "blocks, or if this node does not have the given block available, the transaction will not be found.\n"
                "DEPRECATED: for now, it also works for transactions with unspent outputs.\n"

                "\nReturn the raw transaction data.\n"
                "\nIf verbose is 'true', returns an Object with information about 'txid'.\n"
                "If verbose is 'false' or omitted, returns a string that is serialized, hex-encoded data for 'txid'.\n"

                "\nArguments:\n"
                "1. \"txid\"      (string, required) The transaction id\n"
                "2. verbose     (bool, optional, default=false) If false, return a string, otherwise return a json object\n"
                "3. \"blockhash\" (string, optional) The block in which to look for the transaction\n"

                "\nResult (if verbose is not set or set to false):\n"
                "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

                "\nResult (if verbose is set to true):\n"
                "{\n"
                "  \"in_active_chain\": b, (bool) Whether specified block is in the active chain or not (only present with explicit \"blockhash\" argument)\n"
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
                "           \"address\"        (string) animecoin address\n"
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
                + HelpExampleCli("getrawtransaction", "\"mytxid\" true")
                + HelpExampleRpc("getrawtransaction", "\"mytxid\", true")
                + HelpExampleCli("getrawtransaction", "\"mytxid\" false \"myblockhash\"")
                + HelpExampleCli("getrawtransaction", "\"mytxid\" true \"myblockhash\"")
        );

    LOCK(cs_main);

    bool in_active_chain = true;
    uint256 hash = ParseHashV(request.params[0], "parameter 1");
    CBlockIndex* blockindex = nullptr;

    // Accept either a bool (true) or a num (>=1) to indicate verbose output.
    bool fVerbose = false;
    if (request.params.size() > 1) {
        fVerbose = request.params[1].isNum() ? (request.params[1].get_int() != 0) : request.params[1].get_bool();
    }

    if (!request.params[2].isNull()) {
        uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
        if (!blockhash.IsNull()) {
            BlockMap::iterator it = mapBlockIndex.find(blockhash);
            if (it == mapBlockIndex.end()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
            }
            blockindex = it->second;
            in_active_chain = chainActive.Contains(blockindex);
        }
    }

    CTransaction tx;
    uint256 hash_block;
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hash_block, true, blockindex)) {
        std::string errmsg;
        if (blockindex) {
            if (!(blockindex->nStatus & BLOCK_HAVE_DATA)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such transaction found in the provided block";
        } else {
            errmsg = fTxIndex
              ? "No such mempool or blockchain transaction"
              : "No such mempool transaction. Use -txindex to enable blockchain transaction queries";
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
    }
    string strHex = EncodeHexTx(tx);

    if (!fVerbose) {
        return strHex;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", strHex);
    if (blockindex) result.pushKV("in_active_chain", in_active_chain);
    TxToJSON(tx, hash_block, result);
    return result;
}

UniValue gettxoutproof(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw runtime_error(
            "gettxoutproof [\"txid\",...] ( blockhash )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
            "\nNOTE: By default this function only works sometimes. This is when there is an\n"
            "unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option or\n"
            "specify the block in which the transaction is included in manually (by blockhash).\n"
            "\nReturn the raw transaction data.\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"blockhash\"   (string, optional) If specified, looks for txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n"
        );

    set<uint256> setTxids;
    uint256 oneTxid;
    UniValue txids = request.params[0].get_array();
    for (unsigned int idx = 0; idx < txids.size(); idx++) {
        const UniValue& txid = txids[idx];
        if (txid.get_str().length() != 64 || !IsHex(txid.get_str()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ")+txid.get_str());
        uint256 hash(uint256S(txid.get_str()));
        if (setTxids.count(hash))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ")+txid.get_str());
       setTxids.insert(hash);
       oneTxid = hash;
    }

    LOCK(cs_main);

    CBlockIndex* pblockindex = nullptr;

    uint256 hashBlock;
    if (request.params.size() > 1)
    {
        hashBlock = uint256S(request.params[1].get_str());
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        pblockindex = mapBlockIndex[hashBlock];
    } else {
        const Coin& coin = AccessByTxid(*pcoinsTip, oneTxid);
        if (!coin.IsSpent() && coin.nHeight > 0 && coin.nHeight <= chainActive.Height()) {
            pblockindex = chainActive[coin.nHeight];
        }
    }

    if (pblockindex == nullptr)
    {
        CTransaction tx;
        if (!GetTransaction(oneTxid, tx, Params().GetConsensus(), hashBlock, false) || hashBlock.IsNull())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        pblockindex = mapBlockIndex[hashBlock];
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    unsigned int ntxFound = 0;
    for (const auto& tx : block.vtx)
        if (setTxids.count(tx->GetHash()))
            ntxFound++;
    if (ntxFound != setTxids.size())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock mb(block, setTxids);
    ssMB << mb;
    std::string strHex = HexStr(ssMB.begin(), ssMB.end());
    return strHex;
}

UniValue verifytxoutproof(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof generated by gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is invalid\n"
        );

    CDataStream ssMB(ParseHexV(request.params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    UniValue res(UniValue::VARR);

    vector<uint256> vMatch;
    vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
        return res;

    LOCK(cs_main);

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

    for (const uint256& hash : vMatch)
        res.push_back(hash.GetHex());
    return res;
}

UniValue createrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw runtime_error(
                "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,\"data\":\"hex\",...} ( locktime )\n"
                "\nCreate a transaction spending the given inputs and creating new outputs.\n"
                "Outputs can be addresses or data.\n"
                "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n"

                "\nArguments:\n"
                "1. \"inputs\"                (string, required) A json array of json objects\n"
                "     [\n"
                "       {\n"
                "         \"txid\":\"id\",    (string, required) The transaction id\n"
                "         \"vout\":n        (numeric, required) The output number\n"
                "         \"sequence\":n    (numeric, optional) The sequence number\n"
                "       }\n"
                "       ,...\n"
                "     ]\n"
                "2. \"outputs\"               (string, required) a json object with outputs\n"
                "    {\n"
                "      \"address\": x.xxx,    (numeric or string, required) The key is the animecoin address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
                "      \"data\": \"hex\"      (string, required) The key is \"data\", the value is hex encoded data\n"
                "      ,...\n"
                "    }\n"
                "3. locktime                  (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
                "\nResult:\n"
                "\"transaction\"              (string) hex string of the transaction\n"

                "\nExamples\n"
                + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
                + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"")
                + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
                + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"data\\\":\\\"00010203\\\"}\"")
            );

    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VARR, UniValue::VOBJ, UniValue::VNUM}, true);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    UniValue inputs = request.params[0].get_array();
    UniValue sendTo = request.params[1].get_obj();

    CMutableTransaction rawTx;

    if (request.params.size() > 2 && !request.params[2].isNull()) {
        int64_t nLockTime = request.params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

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

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            else
                nSequence = (uint32_t)seqNr64;
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    set<CBitcoinAddress> setAddress;
    vector<string> addrList = sendTo.getKeys();
    for (const string& name_ : addrList) {
        if (name_ == "data") {
            std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(),"Data");

            CTxOut out(0, CScript() << OP_RETURN << data);
            rawTx.vout.push_back(out);
        } else {
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
    }

    return EncodeHexTx(rawTx);
}

UniValue decoderawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
                "decoderawtransaction \"hexstring\"\n"
                "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

                "\nArguments:\n"
                "1. \"hexstring\"      (string, required) The transaction hex string\n"

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

    RPCTypeCheck(request.params, {UniValue::VSTR});

    CTransaction tx;

    if (!DecodeHexTx(tx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(tx, uint256(), result);

    return result;
}

UniValue decodescript(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "decodescript \"hexstring\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hexstring\"     (string) the hex encoded script\n"
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

    RPCTypeCheck(request.params, {UniValue::VSTR});

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.pushKV("p2sh", CBitcoinAddress(CScriptID(script)).ToString());
    return r;
}

UniValue signrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
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
                        "3. \"privkeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
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

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VARR, UniValue::VSTR}, true);

    vector<unsigned char> txData(ParseHexV(request.params[0], "argument 1"));
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
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = request.params[2].get_array();
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
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        UniValue prevTxs = request.params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                const Coin& coin = view.AccessCoin(out);
                if (!coin.IsSpent() && coin.out.scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin.out.scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                Coin newcoin;
                newcoin.out.scriptPubKey = scriptPubKey;
                newcoin.out.nValue = 0;
                // For a future witness patch, use newcoin.out.nValue = AmountFromValue(find_value(prevOut, "amount"));
                newcoin.nHeight = 1;
                view.AddCoin(out, std::move(newcoin), true);
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"txid", UniValueType(UniValue::VSTR)},
                        {"vout", UniValueType(UniValue::VNUM)},
                        {"scriptPubKey", UniValueType(UniValue::VSTR)},
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                    });
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
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        static map<string, int> mapSigHashValues =
        {
            {string("ALL"), int(SIGHASH_ALL)},
            {string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY)},
            {string("NONE"), int(SIGHASH_NONE)},
            {string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY)},
            {string("SINGLE"), int(SIGHASH_SINGLE)},
            {string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY)}
        };
        string strHashType = request.params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        // For witness patch, use const CAmount& amount = coin.out.nValue;

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
    result.pushKV("hex", EncodeHexTx(mergedTx));
    result.pushKV("complete", fComplete);

    return result;
}

UniValue sendrawtransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
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

    std::promise<void> promise;

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL});

    // parse hex string from parameter
    CTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();

    CAmount nMaxRawTxFee = maxTxFee;
    if (request.params.size() > 1 && request.params[1].get_bool())
        nMaxRawTxFee = 0;

    { // cs_main scope
    LOCK(cs_main);
    CCoinsViewCache &view = *pcoinsTip;
    bool fHaveChain = false;
    for (size_t o = 0; !fHaveChain && o < tx.vout.size(); o++) {
        const Coin& existingCoin = view.AccessCoin(COutPoint(hashTx, o));
        fHaveChain = !existingCoin.IsSpent();
    }
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, false, nMaxRawTxFee)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        } else {
            // If wallet is enabled, ensure that the wallet has been made aware
            // of the new transaction prior to returning. This prevents a race
            // where a user might call sendrawtransaction with a transaction
            // to/from their wallet, immediately call some wallet RPC, and get
            // a stale result because callbacks have not yet been processed.
            CallFunctionInValidationInterfaceQueue([&promise] {
                promise.set_value();
            });
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }

    } // cs_main

    promise.get_future().wait();

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    CInv inv(MSG_TX, hashTx);
    g_connman->ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });

    return hashTx.GetHex();
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
  { "rawtransactions",    "getrawtransaction",      &getrawtransaction,      true,  {"txid","verbose","blockhash"} },
  { "rawtransactions",    "createrawtransaction",   &createrawtransaction,   true,  {"transactions","outputs","locktime"} },
  { "rawtransactions",    "decoderawtransaction",   &decoderawtransaction,   true,  {"hexstring"} },
  { "rawtransactions",    "decodescript",           &decodescript,           true,  {"hexstring"} },
  { "rawtransactions",    "sendrawtransaction",     &sendrawtransaction,     false, {"hexstring","allowhighfees"} },
  { "rawtransactions",    "signrawtransaction",     &signrawtransaction,     false, {"hexstring","prevtxs","privkeys","sighashtype"} }, /* uses wallet if enabled */

  { "blockchain",         "gettxoutproof",          &gettxoutproof,          true,  {"txids", "blockhash"} },
  { "blockchain",         "verifytxoutproof",       &verifytxoutproof,       true,  {"proof"} },
};

void RegisterRawTransactionRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}