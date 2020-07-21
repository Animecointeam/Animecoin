// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "arith_uint256.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "miner.h"
#include "net.h"
#include "policy/fees.h"
#include "pow.h"
#include "rpc/server.h"
#include "util.h"
#include "validation.h"
#include "validationinterface.h"

#include <memory>
#include <stdint.h>

#include <univalue.h>

using namespace std;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
UniValue GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = chainActive.Tip();

    if (height >= 0 && height < chainActive.Height())
        pb = chainActive[height];

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return (int64_t)(workDiff.getdouble() / timeDiff);
}

UniValue getnetworkhashps(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw runtime_error(
            "getnetworkhashps ( nblocks height )\n"
            "\nReturns the estimated network hashes per second based on the last n blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, optional, default=120) The number of blocks, or -1 for blocks since last difficulty change.\n"
            "2. height      (numeric, optional, default=-1) To estimate at the time of the given height.\n"
            "\nResult:\n"
            "x             (numeric) Hashes per second estimated\n"
            "\nExamples:\n"
            + HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
       );

    LOCK(cs_main);
    return GetNetworkHashPS(!request.params[0].isNull() ? request.params[0].get_int() : 120, !request.params[1].isNull() ? request.params[1].get_int() : -1);
}

UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript)
{
    static const int nInnerLoopCount = 0x10000;
    int nHeightStart = 0;
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeightStart = chainActive.Height();
        nHeight = nHeightStart;
        nHeightEnd = nHeightStart+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    while (nHeight < nHeightEnd)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce);
        }
        while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount && !CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0) {
            break;
        }
        if (pblock->nNonce == nInnerLoopCount) {
            continue;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }
    return blockHashes;
}

UniValue generate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "generate nblocks ( maxtries )\n"
            "\nMine up to nblocks blocks immediately (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n"
            + HelpExampleCli("generate", "11")
        );

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (request.params.size() > 1) {
        nMaxTries = request.params[1].get_int();
    }

    std::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    //throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, true);
}

UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw runtime_error(
            "generatetoaddress nblocks address (maxtries)\n"
            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. address      (string, required) The address to send the newly generated animecoin to.\n"
            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
        );

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (!request.params[2].isNull()) {
        nMaxTries = request.params[2].get_int();
    }

    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");

    std::shared_ptr<CReserveScript> coinbaseScript = std::make_shared<CReserveScript>();
    coinbaseScript->reserveScript = GetScriptForDestination(address.Get());

    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
}

UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblocksize\": nnn,   (numeric) The last block size\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"            (string) Current errors\n"
            "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
            "  \"pooledtx\": n              (numeric) The size of the mem pool\n"
            "  \"testnet\": true|false      (boolean) If using testnet or not\n"
            "  \"chain\": \"xxxx\",         (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           (int)chainActive.Height());
    obj.pushKV("currentblocksize", (uint64_t)nLastBlockSize);
    obj.pushKV("currentblocktx",   (uint64_t)nLastBlockTx);
    obj.pushKV("difficulty",       (double)GetDifficulty());
    obj.pushKV("errors",           GetWarnings("statusbar"));
    obj.pushKV("networkhashps",    getnetworkhashps(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("testnet",          Params().TestnetToBeDeprecatedFieldRPC());
    obj.pushKV("chain",            Params().NetworkIDString());
    return obj;
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue prioritisetransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
                "prioritisetransaction <txid> <priority delta> <fee delta>\n"
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
                "\nArguments:\n"
                "1. \"txid\"       (string, required) The transaction id.\n"
                "2. priority_delta (numeric, required) The priority to add or subtract.\n"
                "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
                "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize) \n"
                "3. fee_delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
                "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
                "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
                "\nResult\n"
                "true              (boolean) Returns true\n"
                "\nExamples:\n"
                + HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
                + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
            );

    LOCK(cs_main);

    uint256 hash = ParseHashStr(request.params[0].get_str(), "txid");

    CAmount nAmount = request.params[2].get_int64();

    mempool.PrioritiseTransaction(hash, request.params[0].get_str(), request.params[1].get_real(), nAmount);
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

UniValue getblocktemplate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
                "getblocktemplate ( \"jsonrequestobject\" )\n"
                "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
                "It returns data needed to construct a block to work on.\n"
                "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

                "\nArguments:\n"
                "1. template_request         (json object, optional) A json object in the following spec\n"
                "     {\n"
                "       \"mode\":\"template\"    (string, optional) This must be set to \"template\" or omitted\n"
                "       \"capabilities\":[       (array, optional) A list of strings\n"
                "           \"support\"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
                "           ,...\n"
                "         ]\n"
                "     }\n"
                "\n"

                "\nResult:\n"
                "{\n"
                "  \"version\" : n,                    (numeric) The block version\n"
                "  \"previousblockhash\" : \"xxxx\",    (string) The hash of current highest block\n"
                "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
                "      {\n"
                "         \"data\" : \"xxxx\",          (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
                "         \"hash\" : \"xxxx\",          (string) hash/id encoded in little-endian hexadecimal\n"
                "         \"depends\" : [              (array) array of numbers \n"
                "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
                "             ,...\n"
                "         ],\n"
                "         \"fee\": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
                "         \"sigops\" : n,               (numeric) total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any\n"
                "         \"required\" : true|false     (boolean) if provided and true, this transaction must be in the final block\n"
                "      }\n"
                "      ,...\n"
                "  ],\n"
                "  \"coinbaseaux\" : {                  (json object) data that should be included in the coinbase's scriptSig content\n"
                "      \"flags\" : \"flags\"            (string) \n"
                "  },\n"
                "  \"coinbasevalue\" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
                "  \"coinbasetxn\" : { ... },           (json object) information for coinbase transaction\n"
                "  \"target\" : \"xxxx\",               (string) The hash target\n"
                "  \"mintime\" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
                "  \"mutable\" : [                      (array of string) list of ways the block template may be changed \n"
                "     \"value\"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
                "     ,...\n"
                "  ],\n"
                "  \"noncerange\" : \"00000000ffffffff\",   (string) A range of valid nonces\n"
                "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
                "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
                "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
                "  \"bits\" : \"xxx\",                 (string) compressed target of next block\n"
                "  \"height\" : n                      (numeric) The height of the next block\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getblocktemplate", "")
                + HelpExampleRpc("getblocktemplate", "")
             );

    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Animecoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Animecoin is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WAIT_LOCK(g_best_block_mutex, lock);
            while (g_best_block == hashWatchedChain && IsRPCRunning())
            {
                if (g_best_block_cv.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    if (pindexPrev != chainActive.Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.Tip();
        nStart = GetTime();

        // Create new block
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
    pblock->nNonce = 0;

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));

        entry.pushKV("hash", txHash.GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn& in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", deps);

        int index_in_template = i - 1;
        entry.pushKV("fee", pblocktemplate->vTxFees[index_in_template]);
        entry.pushKV("sigops", pblocktemplate->vTxSigOps[index_in_template]);

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.pushKV("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end()));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    static UniValue aMutable(UniValue::VARR);
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
        // Extra GBT compatibility for miners post getwork removal.
        aMutable.push_back("version/force");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", aCaps);
    result.pushKV("version", pblock->nVersion);

    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("transactions", transactions);
    result.pushKV("coinbaseaux", aux);
    result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->vout[0].nValue);
    result.pushKV("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1);
    result.pushKV("mutable", aMutable);
    result.pushKV("noncerange", "00000000ffffffff");
    result.pushKV("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS);
    result.pushKV("sizelimit", (int64_t)MAX_BLOCK_SIZE);
    result.pushKV("curtime", pblock->GetBlockTime());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));

    return result;
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue submitblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
                "submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
                "\nAttempts to submit new block to network.\n"
                "The 'jsonparametersobject' parameter is currently ignored.\n"
                "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

                "\nArguments\n"
                "1. \"hexdata\"        (string, required) the hex-encoded block data to submit\n"
                "2. \"parameters\"     (string, optional) object of optional parameters\n"
                "    {\n"
                "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
                "    }\n"
                "\nResult:\n"
                "\nExamples:\n"
                + HelpExampleCli("submitblock", "\"mydata\"")
                + HelpExampleRpc("submitblock", "\"mydata\"")
            );

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, nullptr);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (!sc.found)
        return "inconclusive";
    return BIP22ValidationResult(sc.state);
}

UniValue estimatefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "estimatefee nblocks\n"
            "\nDEPRECATED. Please use estimatesmartfee for more intelligent estimates."
            "\nEstimates the approximate fee per kilobyte\n"
            "needed for a transaction to begin confirmation\n"
            "within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "n :    (numeric) estimated fee-per-kilobyte\n"
            "\n"
            "-1.0 is returned if not enough transactions and\n"
            "blocks have been observed to make an estimate.\n"
            "-1 is always returned for nblocks == 1 as it is impossible to calculate\n"
            "a fee that is high enough to get reliably included in the next block.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatefee", "6")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

    CFeeRate feeRate = ::feeEstimator.estimateFee(nBlocks);
    if (feeRate == CFeeRate(0))
        return -1.0;

    return ValueFromAmount(feeRate.GetFeePerK());
}

UniValue estimatepriority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "estimatepriority nblocks\n"
            "\nDEPRECATED. Estimates the approximate priority a zero-fee transaction needs to begin\n"
            "within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "n :    (numeric) estimated priority\n"
            "\n"
            "-1.0 is returned if not enough transactions and\n"
            "blocks have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatepriority", "6")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

    return mempool.estimatePriority(nBlocks);
}

UniValue estimatesmartfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "estimatesmartfee nblocks (conservative)\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks       (numeric)\n"
            "2. conservative  (bool, optional, default=true) Whether to return a more conservative estimate which\n"
            "                 also satisfies a longer history. A conservative estimate potentially returns a higher\n"
            "                 feerate and is more likely to be sufficient for the desired target, but is not as\n"
            "                 responsive to short term drops in the prevailing fee market\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric) estimate fee-per-kilobyte (in BTC)\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However it will not return a value below the mempool reject fee.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartfee", "6")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();
    bool conservative = true;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VBOOL);
        conservative = request.params[1].get_bool();
    }

    UniValue result(UniValue::VOBJ);
    int answerFound;
    CFeeRate feeRate = ::feeEstimator.estimateSmartFee(nBlocks, &answerFound, ::mempool, conservative);
    result.pushKV("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK()));
    result.pushKV("blocks", answerFound);
    return result;
}

UniValue estimaterawfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1|| request.params.size() > 3)
        throw std::runtime_error(
            "estimaterawfee nblocks (threshold horizon)\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nWARNING: This is an advanced API call that is tightly coupled to the specific\n"
            "         implementation of fee estimation. The parameters it can be called with\n"
            "         and the results it returns will change if the internal implementation changes.\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible. Uses virtual transaction size as defined\n"
            "in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "2. threshold   (numeric, optional) The proportion of transactions in a given feerate range that must have been\n"
            "               confirmed within nblocks in order to consider those feerates as high enough and proceed to check\n"
            "               lower buckets.  Default: 0.95\n"
            "3. horizon     (numeric, optional) How long a history of estimates to consider. 0=short, 1=medium, 2=long.\n"
            "               Default: 1\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,        (numeric) estimate fee-per-kilobyte (in BTC)\n"
            "  \"decay\" : x.x,          (numeric) exponential decay (per block) for historical moving average of confirmation data\n"
            "  \"scale\" : x,            (numeric) The resolution of confirmation targets at this time horizon\n"
            "  \"pass\" : {              (json object) information about the lowest range of feerates to succeed in meeting the threshold\n"
            "      \"startrange\" : x.x,     (numeric) start of feerate range\n"
            "      \"endrange\" : x.x,       (numeric) end of feerate range\n"
            "      \"withintarget\" : x.x,   (numeric) number of txs over history horizon in the feerate range that were confirmed within target\n"
            "      \"totalconfirmed\" : x.x, (numeric) number of txs over history horizon in the feerate range that were confirmed at any point\n"
            "      \"inmempool\" : x.x,      (numeric) current number of txs in mempool in the feerate range unconfirmed for at least target blocks\n"
            "      \"leftmempool\" : x.x,    (numeric) number of txs over history horizon in the feerate range that left mempool unconfirmed after target\n"
            "  }\n"
            "  \"fail\" : { ... }        (json object) information about the highest range of feerates to fail to meet the threshold\n"
            "}\n"
            "\n"
            "A negative feerate is returned if no answer can be given.\n"
            "\nExample:\n"
            + HelpExampleCli("estimaterawfee", "6 0.9 1")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VNUM, UniValue::VNUM}, true);
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    int nBlocks = request.params[0].get_int();
    double threshold = 0.95;
    if (!request.params[1].isNull())
        threshold = request.params[1].get_real();
    FeeEstimateHorizon horizon = FeeEstimateHorizon::MED_HALFLIFE;
    if (!request.params[2].isNull()) {
        int horizonInt = request.params[2].get_int();
        if (horizonInt < 0 || horizonInt > 2) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid horizon for fee estimates");
        } else {
            horizon = (FeeEstimateHorizon)horizonInt;
        }
    }
    UniValue result(UniValue::VOBJ);
    CFeeRate feeRate;
    EstimationResult buckets;
    feeRate = ::feeEstimator.estimateRawFee(nBlocks, threshold, horizon, &buckets);

    result.pushKV("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK()));
    result.pushKV("decay", buckets.decay);
    result.pushKV("scale", (int)buckets.scale);
    UniValue passbucket(UniValue::VOBJ);
    passbucket.pushKV("startrange", round(buckets.pass.start));
    passbucket.pushKV("endrange", round(buckets.pass.end));
    passbucket.pushKV("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0);
    passbucket.pushKV("totalconfirmed", round(buckets.pass.totalConfirmed * 100.0) / 100.0);
    passbucket.pushKV("inmempool", round(buckets.pass.inMempool * 100.0) / 100.0);
    passbucket.pushKV("leftmempool", round(buckets.pass.leftMempool * 100.0) / 100.0);
    result.pushKV("pass", passbucket);
    UniValue failbucket(UniValue::VOBJ);
    failbucket.pushKV("startrange", round(buckets.fail.start));
    failbucket.pushKV("endrange", round(buckets.fail.end));
    failbucket.pushKV("withintarget", round(buckets.fail.withinTarget * 100.0) / 100.0);
    failbucket.pushKV("totalconfirmed", round(buckets.fail.totalConfirmed * 100.0) / 100.0);
    failbucket.pushKV("inmempool", round(buckets.fail.inMempool * 100.0) / 100.0);
    failbucket.pushKV("leftmempool", round(buckets.fail.leftMempool * 100.0) / 100.0);
    result.pushKV("fail", failbucket);
    return result;
}

UniValue estimatesmartpriority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "estimatesmartpriority nblocks\n"
            "\nDEPRECATED. WARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "{\n"
            "  \"priority\" : x.x,    (numeric) estimated priority\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However if the mempool reject fee is set it will return 1e9 * MAX_MONEY.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartpriority", "6")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();

    UniValue result(UniValue::VOBJ);
    int answerFound;
    double priority = mempool.estimateSmartPriority(nBlocks, &answerFound);
    result.pushKV("priority", priority);
    result.pushKV("blocks", answerFound);
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
  { "mining",             "getnetworkhashps",       &getnetworkhashps,       true,  {"nblocks","height"} },
  { "mining",             "getmininginfo",          &getmininginfo,          true,  {} },
  { "mining",             "prioritisetransaction",  &prioritisetransaction,  true,  {"txid","priority_delta","fee_delta"} },
  { "mining",             "getblocktemplate",       &getblocktemplate,       true,  {"template_request"} },
  { "mining",             "submitblock",            &submitblock,            true,  {"hexdata","parameters"} },

  { "generating",         "generate",               &generate,               true,  {"nblocks","maxtries"} },
  { "generating",         "generatetoaddress",      &generatetoaddress,      true,  {"nblocks","address","maxtries"} },

  { "util",               "estimatefee",            &estimatefee,            true,  {"nblocks"} },
  { "util",               "estimatepriority",       &estimatepriority,       true,  {"nblocks"} },
  { "util",               "estimatesmartfee",       &estimatesmartfee,       true,  {"nblocks", "conservative"} },
  { "hidden",             "estimaterawfee",         &estimaterawfee,         true,  {"nblocks", "threshold", "horizon"} },
  { "util",               "estimatesmartpriority",  &estimatesmartpriority,  true,  {"nblocks"} },
};

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}