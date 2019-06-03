// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "main.h"
#include "rpcserver.h"
#include "streams.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "version.h"

#include <boost/algorithm/string.hpp>

#include "univalue/univalue.h"

using namespace std;

enum RetFormat {
    RF_UNDEF,
    RF_BINARY,
    RF_HEX,
    RF_JSON,
};

static const struct {
    enum RetFormat rf;
    const char* name;
} rf_names[] = {
      {RF_UNDEF, ""},
      {RF_BINARY, "bin"},
      {RF_HEX, "hex"},
      {RF_JSON, "json"},
};

class RestErr
{
public:
    enum HTTPStatusCode status;
    string message;
};

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
extern UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false);

static RestErr RESTERR(enum HTTPStatusCode status, string message)
{
    RestErr re;
    re.status = status;
    re.message = message;
    return re;
}

static enum RetFormat ParseDataFormat(vector<string>& params, const string strReq)
{
    boost::split(params, strReq, boost::is_any_of("."));
    if (params.size() > 1) {
        for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
            if (params[1] == rf_names[i].name)
                return rf_names[i].rf;
    }

    return rf_names[0].rf;
}

static string AvailableDataFormatsString()
{
    string formats = "";
    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (strlen(rf_names[i].name) > 0) {
            formats.append(".");
            formats.append(rf_names[i].name);
            formats.append(", ");
        }

    if (formats.length() > 0)
        return formats.substr(0, formats.length() - 2);

    return formats;
}

static bool ParseHashStr(const string& strReq, uint256& v)
{
    if (!IsHex(strReq) || (strReq.size() != 64))
        return false;

    v.SetHex(strReq);
    return true;
}

static bool rest_headers(AcceptedConnection* conn,
                         string& strReq,
                         map<string, string>& mapHeaders,
                         bool fRun)
{
    vector<string> params;
    const RetFormat rf = ParseDataFormat(params, strReq);
    vector<string> path;
    boost::split(path, params[0], boost::is_any_of("/"));

    if (path.size() != 2)
        throw RESTERR(HTTP_BAD_REQUEST, "No header count specified. Use /rest/headers/<count>/<hash>.<ext>.");

    long count = strtol(path[0].c_str(), NULL, 10);
    if (count < 1 || count > 2000)
        throw RESTERR(HTTP_BAD_REQUEST, "Header count out of range: " + path[0]);

    string hashStr = path[1];
    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        throw RESTERR(HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    std::vector<CBlockHeader> headers;
    headers.reserve(count);
    {
        LOCK(cs_main);
        BlockMap::const_iterator it = mapBlockIndex.find(hash);
        const CBlockIndex *pindex = (it != mapBlockIndex.end()) ? it->second : NULL;
        while (pindex != NULL && chainActive.Contains(pindex)) {
            headers.push_back(pindex->GetBlockHeader());
            if (headers.size() == (unsigned long)count)
                break;
            pindex = chainActive.Next(pindex);
        }
    }

    CDataStream ssHeader(SER_NETWORK, PROTOCOL_VERSION);
    BOOST_FOREACH(const CBlockHeader &header, headers) {
        ssHeader << header;
    }

    switch (rf) {
    case RF_BINARY: {
        string binaryHeader = ssHeader.str();
        conn->stream() << HTTPReplyHeader(HTTP_OK, fRun, binaryHeader.size(), "application/octet-stream") << binaryHeader << std::flush;
        return true;
    }

    case RF_HEX: {
        string strHex = HexStr(ssHeader.begin(), ssHeader.end()) + "\n";
        conn->stream() << HTTPReply(HTTP_OK, strHex, fRun, false, "text/plain") << std::flush;
        return true;
    }

    default: {
        throw RESTERR(HTTP_NOT_FOUND, "output format not found (available: .bin, .hex)");
    }
    }

    // not reached
    return true; // continue to process further HTTP reqs on this cxn
}

static bool rest_block(AcceptedConnection* conn,
                       string& strReq,
                       map<string, string>& mapHeaders,
                       bool fRun,
                       bool showTxDetails)
{
    vector<string> params;
    const RetFormat rf = ParseDataFormat(params, strReq);

    string hashStr = params[0];
    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        throw RESTERR(HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    CBlock block;
    CBlockIndex* pblockindex = nullptr;
    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw RESTERR(HTTP_NOT_FOUND, hashStr + " not found");

        pblockindex = mapBlockIndex[hash];
        if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
            throw RESTERR(HTTP_NOT_FOUND, hashStr + " not available (pruned data)");

        if (!ReadBlockFromDisk(block, pblockindex))
            throw RESTERR(HTTP_NOT_FOUND, hashStr + " not found");
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
    ssBlock << block;

    switch (rf) {
    case RF_BINARY: {
        string binaryBlock = ssBlock.str();
        conn->stream() << HTTPReplyHeader(HTTP_OK, fRun, binaryBlock.size(), "application/octet-stream") << binaryBlock << std::flush;
        return true;
    }

    case RF_HEX: {
        string strHex = HexStr(ssBlock.begin(), ssBlock.end()) + "\n";
        conn->stream() << HTTPReply(HTTP_OK, strHex, fRun, false, "text/plain") << std::flush;
        return true;
    }

    case RF_JSON: {
        UniValue objBlock = blockToJSON(block, pblockindex, showTxDetails);
        string strJSON = objBlock.write() + "\n";
        conn->stream() << HTTPReply(HTTP_OK, strJSON, fRun) << std::flush;
        return true;
    }

    default: {
        throw RESTERR(HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }

    // not reached
    return true; // continue to process further HTTP reqs on this cxn
}

static bool rest_block_extended(AcceptedConnection* conn,
                       string& strReq,
                       map<string, string>& mapHeaders,
                       bool fRun)
{
    return rest_block(conn, strReq, mapHeaders, fRun, true);
}

static bool rest_block_notxdetails(AcceptedConnection* conn,
                       string& strReq,
                       map<string, string>& mapHeaders,
                       bool fRun)
{
    return rest_block(conn, strReq, mapHeaders, fRun, false);
}

static bool rest_chaininfo(AcceptedConnection* conn,
                                   string& strReq,
                                   map<string, string>& mapHeaders,
                                   bool fRun)
{
    vector<string> params;
    const RetFormat rf = ParseDataFormat(params, strReq);

    switch (rf) {
    case RF_JSON: {
        UniValue rpcParams(UniValue::VARR);
        UniValue chainInfoObject = getblockchaininfo(rpcParams, false);

        string strJSON = chainInfoObject.write() + "\n";
        conn->stream() << HTTPReply(HTTP_OK, strJSON, fRun) << std::flush;
        return true;
    }
    default: {
        throw RESTERR(HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }

    // not reached
    return true; // continue to process further HTTP reqs on this cxn
}

static bool rest_tx(AcceptedConnection* conn,
                    string& strReq,
                    map<string, string>& mapHeaders,
                    bool fRun)
{
    vector<string> params;
    const RetFormat rf = ParseDataFormat(params, strReq);

    string hashStr = params[0];
    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        throw RESTERR(HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    CTransaction tx;
    uint256 hashBlock = uint256();
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw RESTERR(HTTP_NOT_FOUND, hashStr + " not found");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;

    switch (rf) {
    case RF_BINARY: {
        string binaryTx = ssTx.str();
        conn->stream() << HTTPReplyHeader(HTTP_OK, fRun, binaryTx.size(), "application/octet-stream") << binaryTx << std::flush;
        return true;
    }

    case RF_HEX: {
        string strHex = HexStr(ssTx.begin(), ssTx.end()) + "\n";
        conn->stream() << HTTPReply(HTTP_OK, strHex, fRun, false, "text/plain") << std::flush;
        return true;
    }

    case RF_JSON: {
        UniValue objTx(UniValue::VOBJ);
        TxToJSON(tx, hashBlock, objTx);
        string strJSON = objTx.write() + "\n";
        conn->stream() << HTTPReply(HTTP_OK, strJSON, fRun) << std::flush;
        return true;
    }

    default: {
        throw RESTERR(HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }

    // not reached
    return true; // continue to process further HTTP reqs on this cxn
}

static const struct {
    const char* prefix;
    bool (*handler)(AcceptedConnection* conn,
                    string& strURI,
                    map<string, string>& mapHeaders,
                    bool fRun);
} uri_prefixes[] = {
      {"/rest/tx/", rest_tx},
      {"/rest/block/notxdetails/", rest_block_notxdetails},
      {"/rest/block/", rest_block_extended},
      {"/rest/chaininfo", rest_chaininfo},
      {"/rest/headers/", rest_headers},
};

bool HTTPReq_REST(AcceptedConnection* conn,
                  string& strURI,
                  map<string, string>& mapHeaders,
                  bool fRun)
{
    try {
        std::string statusmessage;
        if (RPCIsInWarmup(&statusmessage))
            throw RESTERR(HTTP_SERVICE_UNAVAILABLE, "Service temporarily unavailable: " + statusmessage);

        for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++) {
            unsigned int plen = strlen(uri_prefixes[i].prefix);
            if (strURI.substr(0, plen) == uri_prefixes[i].prefix) {
                string strReq = strURI.substr(plen);
                return uri_prefixes[i].handler(conn, strReq, mapHeaders, fRun);
            }
        }
    } catch (const RestErr& re) {
        conn->stream() << HTTPReply(re.status, re.message + "\r\n", false, false, "text/plain") << std::flush;
        return false;
    }

    conn->stream() << HTTPError(HTTP_NOT_FOUND, false) << std::flush;
    return false;
}