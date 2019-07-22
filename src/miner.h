// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "txmempool.h"

#include <stdint.h>
#include <memory>

class CBlock;
class CBlockHeader;
class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;

namespace Consensus { class Params; }

static const bool DEFAULT_GENERATE = false;
static const int DEFAULT_GENERATE_THREADS = 1;

static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate;

/** Run the miner threads */
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams);
/** Generate a new block, without valid proof-of-work */
class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    // A convenience pointer that always refers to the CBlock in pblocktemplate
    CBlock* pblock;

    // Configuration parameters for the block size
    unsigned int nBlockMaxSize, nBlockMinSize;

    // Information on the current status of the block
    uint64_t nBlockSize;
    uint64_t nBlockTx;
    unsigned int nBlockSigOps;
    CAmount nFees;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;
    const CChainParams& chainparams;

    // Variables used for addScoreTxs and addPriorityTxs
    int lastFewTxs;
    bool blockFinished;

public:
    BlockAssembler(const CChainParams& chainparams);
    /** Construct a new block template with coinbase to scriptPubKeyIn */
    CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn);

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(CTxMemPool::txiter iter);

    // Methods for how to add transactions to a block.
    /** Add transactions based on modified feerate */
    void addScoreTxs();
    /** Add transactions based on tx "priority" */
    void addPriorityTxs();

    // helper function for addScoreTxs and addPriorityTxs
    /** Test if tx will still "fit" in the block */
    bool TestForBlock(CTxMemPool::txiter iter);
    /** Test if tx still has unconfirmed parents not yet in block */
    bool isStillDependent(CTxMemPool::txiter iter);
};

/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
/** Check mined block */
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);
void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

extern double dHashesPerSec;
extern int64_t nHPSTimerStart;

#endif // BITCOIN_MINER_H