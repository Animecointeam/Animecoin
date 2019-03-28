// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"
#include "key.h"
#include "txdb.h"
#include "base58.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to
    // be slower. This number is a compromise, as it can't be accurate for
    // every system. When reindexing from a fast disk with a slow CPU, it
    // can be up to 20, while when downloading from a slow network with a
    // fast multicore CPU, it won't be much higher than 1.
    static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64_t nTimeLastCheckpoint;
        int64_t nTransactionsLastCheckpoint;
        double fTransactionsPerDay;
    };

    bool fEnabled = true;

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0,     uint256("0x0000099acc274b7b403a828238bad69414e03a1a51b297a250c0a0da8a337840"))
		( 1,     uint256("0x00000c3849197334206d575b9ab34ff04786ab7776ac72424ffed8dfcd3e5a5b"))
        ;
    static const CCheckpointData data = {
        &mapCheckpoints,
        1390744420, // * UNIX timestamp of last checkpoint block
        0,    		// * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        2880.0      // * estimated number of transactions per day after checkpoint
    };

    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c"))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        978307200,
        0,
        2880.0
    };

    static MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        ;
    static const CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

    const CCheckpointData &Checkpoints() {
        if (Params().NetworkID() == CChainParams::TESTNET)
            return dataTestnet;
        else if (Params().NetworkID() == CChainParams::MAIN)
            return data;
        else
            return dataRegtest;
    }

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (!fEnabled)
            return true;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks) {
        if (pindex==NULL)
            return 0.0;

        int64_t nNow = time(NULL);

        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkpoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (!fEnabled)
            return 0;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (!GetBoolArg("-checkpoints", true))
            return NULL;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }
    
    uint256 GetLatestHardenedCheckpoint()
    {
        LogPrintf("GetLatestHardenedCheckpoint\n");
        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;
        
        return (checkpoints.rbegin()->second);
    }
 
    // ppcoin: synchronized checkpoint (centrally broadcasted)
    uint256 hashSyncCheckpoint = 0;
    uint256 hashPendingCheckpoint = 0;
    CSyncCheckpoint checkpointMessage;
    CSyncCheckpoint checkpointMessagePending;
    uint256 hashInvalidCheckpoint = 0;
    CCriticalSection cs_hashSyncCheckpoint;
    std::string strCheckpointWarning;   
    
    // ppcoin: only descendant of current sync-checkpoint is allowed
    bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
    {
        LogPrintf("ValidateSyncCheckpoint: hashCheckpoint=%s\n", hashCheckpoint.ToString().c_str());

        if ( (hashSyncCheckpoint == 0) || (!mapBlockIndex.count(hashSyncCheckpoint)) )
        {
            // NO SYNC CHECKPOINT
            return true;
        }
        
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        if (!mapBlockIndex.count(hashCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());
        
        CBlockIndex* pindexSyncCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        CBlockIndex* pindexCheckpointRecv = mapBlockIndex[hashCheckpoint];

        if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight)
        {
            // Received an older checkpoint, trace back from current checkpoint
            // to the same height of the received checkpoint to verify
            // that current checkpoint should be a descendant block
            CBlockIndex* pindex = pindexSyncCheckpoint;
            while (pindex->nHeight > pindexCheckpointRecv->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("ValidateSyncCheckpoint: pprev1 null - block index structure failure");
            if (pindex->GetBlockHash() != hashCheckpoint)
            {
                hashInvalidCheckpoint = hashCheckpoint;
                return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
            }
            return false; // ignore older checkpoint
        }

        // Received checkpoint should be a descendant block of the current
        // checkpoint. Trace back to the same height of current checkpoint
        // to verify.
        CBlockIndex* pindex = pindexCheckpointRecv;
        while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");
        if (pindex->GetBlockHash() != hashSyncCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
        
        LogPrintf("ValidateSyncCheckpoint: OK\n");
        return true;
    }

    bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
    {
        if (!pblocktree->WriteSyncCheckpoint(hashCheckpoint))
        {
            return error("WriteSyncCheckpoint(): failed to write to txdb sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }

        hashSyncCheckpoint = hashCheckpoint;
        return true;
    }

    bool IsSyncCheckpointEnforced()
    {
        return (GetBoolArg("-checkpointenforce", true) || mapArgs.count("-checkpointkey")); // checkpoint master node is always enforced
    }

    bool AcceptPendingSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint != 0 && mapBlockIndex.count(hashPendingCheckpoint))
        {
            if (!ValidateSyncCheckpoint(hashPendingCheckpoint))
            {
                hashPendingCheckpoint = 0;
                checkpointMessagePending.SetNull();
                LogPrintf("AcceptPendingSyncCheckpoint: FAIL1\n");
                return false;
            }

            CBlockIndex* pindexCheckpoint = mapBlockIndex[hashPendingCheckpoint];
            if (IsSyncCheckpointEnforced() && !pindexCheckpoint->IsInMainChain())
            {
                CBlock block;
                if (!ReadBlockFromDisk(block, pindexCheckpoint))
                    return error("AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                CValidationState state;
                LogPrintf("AcceptPendingSyncCheckpoint: ConnectTip\n");
                // if (!SetBestChain(state, pindexCheckpoint))
                if (!ConnectTip(state, pindexCheckpoint))
                {
                    hashInvalidCheckpoint = hashPendingCheckpoint;
                    return error("AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                }
            }

            if (!WriteSyncCheckpoint(hashPendingCheckpoint))
                return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
            hashPendingCheckpoint = 0;
            checkpointMessage = checkpointMessagePending;
            checkpointMessagePending.SetNull();
            LogPrintf("AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", hashSyncCheckpoint.ToString().c_str());
            // relay the checkpoint
            if (!checkpointMessage.IsNull())
            {
                BOOST_FOREACH(CNode* pnode, vNodes)
                    checkpointMessage.RelayTo(pnode);
            }
            return true;
        }
        return false;
    }

    // Automatically select a suitable sync-checkpoint 
    uint256 AutoSelectSyncCheckpoint()
    {
        // Search backward for a block with specified depth policy
        // const CBlockIndex *pindex = pindexBest;
        // while (pindex->pprev && pindex->nHeight + (int)GetArg("-checkpointdepth", -1) > pindexBest->nHeight)
        const CBlockIndex *pindex = chainActive.Tip();
        while (pindex->pprev && pindex->nHeight + (int)GetArg("-checkpointdepth", -1) > chainActive.Tip()->nHeight)
              pindex = pindex->pprev;
        return pindex->GetBlockHash();
    }

    // Check against synchronized checkpoint
    bool CheckSyncCheckpoint(const uint256& hashBlock, const CBlockIndex* pindexPrev)
    {
        int nHeight = pindexPrev->nHeight + 1;
        LogPrintf("CheckSyncCheckpoint: nHeight=%d, hashSyncCheckpoint=%s\n", nHeight, hashSyncCheckpoint.ToString().c_str());

        LOCK(cs_hashSyncCheckpoint);
        
        if ((hashSyncCheckpoint == 0) || (mapBlockIndex.count(hashSyncCheckpoint) == 0))
            return true;
            
        // sync-checkpoint should always be accepted block
        // assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];

        if (nHeight > pindexSync->nHeight)
        {
            // trace back to same height as sync-checkpoint
            const CBlockIndex* pindex = pindexPrev;
            while (pindex->nHeight > pindexSync->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("CheckSyncCheckpoint: pprev null - block index structure failure");
            if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != hashSyncCheckpoint)
                return false; // only descendant of sync-checkpoint can pass check
        }
        if (nHeight == pindexSync->nHeight && hashBlock != hashSyncCheckpoint)
            return false; // same height with sync-checkpoint
        if (nHeight < pindexSync->nHeight && !mapBlockIndex.count(hashBlock))
            return false; // lower height than sync-checkpoint
        return true;
    }
    
    bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint == 0)
            return false;
        if (hashBlock == hashPendingCheckpoint)
            return true;
        if (mapOrphanBlocksSyncCheckpoint.count(hashPendingCheckpoint)
            && hashBlock == WantedByOrphan(mapOrphanBlocksSyncCheckpoint[hashPendingCheckpoint]))
            return true;
        return false;
    }

    // ppcoin: reset synchronized checkpoint to last hardened checkpoint
    bool ResetSyncCheckpoint()
    {
        LogPrintf("ResetSyncCheckpoint\n");
        LOCK(cs_hashSyncCheckpoint);
        const uint256& hash = Checkpoints::GetLatestHardenedCheckpoint();
        if (mapBlockIndex.count(hash) && !mapBlockIndex[hash]->IsInMainChain())
        {
            // checkpoint block accepted but not yet in main chain
            LogPrintf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());

            CBlock block;
            if (!ReadBlockFromDisk(block, mapBlockIndex[hash]))
                return error("ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
            CValidationState state;
            LogPrintf("ResetSyncCheckpoint: ConnectTip\n");
            // if (!SetBestChain(state, mapBlockIndex[hash]))
            if (!ConnectTip(state, mapBlockIndex[hash]))
            {
                return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
            }
        }
        else if(!mapBlockIndex.count(hash))
        {
            // checkpoint block not yet accepted
            hashPendingCheckpoint = hash;
            checkpointMessagePending.SetNull();
            LogPrintf("ResetSyncCheckpoint: pending for sync-checkpoint %s\n", hashPendingCheckpoint.ToString().c_str());
        }

        if (!WriteSyncCheckpoint((mapBlockIndex.count(hash) && mapBlockIndex[hash]->IsInMainChain())? hash : Params().HashGenesisBlock()))
            return error("ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
        LogPrintf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n", hashSyncCheckpoint.ToString().c_str());
        return true;
    }

    void AskForPendingSyncCheckpoint(CNode* pfrom)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) && (!mapOrphanBlocksSyncCheckpoint.count(hashPendingCheckpoint)))
            pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
    }
    
    // Verify sync checkpoint master pubkey and reset sync checkpoint if changed
    bool CheckCheckpointPubKey()
    {
        std::string strPubKey = "";
        std::string strMasterPubKey = TestNet() ? CSyncCheckpoint::strTestPubKey : CSyncCheckpoint::strMainPubKey;
        if (!pblocktree->ReadCheckpointPubKey(strPubKey) || strPubKey != strMasterPubKey)
        {
            // write checkpoint master key to db
            if (!pblocktree->WriteCheckpointPubKey(strMasterPubKey))
                return error("CheckCheckpointPubKey() : failed to write new checkpoint master key to db");
            if (!ResetSyncCheckpoint())
                return error("CheckCheckpointPubKey() : failed to reset sync-checkpoint");
        }
        return true;
    }
    
    bool SetCheckpointPrivKey(std::string strPrivKey)
    {
        // Test signing a sync-checkpoint with genesis block
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = Params().HashGenesisBlock();
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(strPrivKey))
            return error("SendSyncCheckpoint: Checkpoint master key invalid");
        // bool fCompressed;
        // CSecret secret = vchSecret.GetSecret(fCompressed);
        CKey secret = vchSecret.GetKey();
        // key.SetSecret(secret, fCompressed); // if key is not correct openssl may crash
        CKey key(secret);
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return false;

        // Test signing successful, proceed
        CSyncCheckpoint::strMasterPrivKey = strPrivKey;
        return true;
    }

    bool SendSyncCheckpoint(uint256 hashCheckpoint)
    {
        LogPrintf("SendSyncCheckpoint: hashCheckpoint=%s\n", hashCheckpoint.ToString().c_str());

        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = hashCheckpoint;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        if (CSyncCheckpoint::strMasterPrivKey.empty())
            return error("SendSyncCheckpoint: Checkpoint master key unavailable.");
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(CSyncCheckpoint::strMasterPrivKey))
            return error("SendSyncCheckpoint: Checkpoint master key invalid");
        // bool fCompressed;
        // CSecret secret = vchSecret.GetSecret(fCompressed);
        CKey secret = vchSecret.GetKey();
        // key.SetSecret(secret, fCompressed); // if key is not correct openssl may crash
        CKey key(secret);
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

        if(!checkpoint.ProcessSyncCheckpoint(NULL))
        {
            LogPrintf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
            return false;
        }

        // Relay checkpoint
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
        return true;
    }

    // Is the sync-checkpoint outside maturity window?
    bool IsMatureSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        // return (nBestHeight >= pindexSync->nHeight + COINBASE_MATURITY);
        return (chainActive.Tip()->nHeight >= pindexSync->nHeight + COINBASE_MATURITY);
    }

    // Is the sync-checkpoint too old?
    bool IsSyncCheckpointTooOld(unsigned int nSeconds)
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (pindexSync->GetBlockTime() + nSeconds < GetAdjustedTime());
    }

    // ppcoin: find block wanted by given orphan block
    uint256 WantedByOrphan(const CBlock* pblockOrphan)
    {
        // Work back to the first block in the orphan chain
        while (mapOrphanBlocksSyncCheckpoint.count(pblockOrphan->hashPrevBlock))
            pblockOrphan = mapOrphanBlocksSyncCheckpoint[pblockOrphan->hashPrevBlock];
        return pblockOrphan->hashPrevBlock;
    }

}

// ppcoin: sync-checkpoint master key
const std::string CSyncCheckpoint::strMainPubKey = "040c73e9dfb014c6cb6a04a98ce728783fc57354db2b6736e768ce5c7c1d018d0b105a99a178161d3f619fa252c68cbdc445b837c0eb07fb76c6e9c9aee0124edf";
const std::string CSyncCheckpoint::strTestPubKey = "04b0253a42b145f638acf1418f52893248ff7748ffb668860ae98c442eca004b93bae2dbcd05bbc2c9bf57d91a36e17c6a68d40f0ba7faf06a4f5e332ea2de92da";
std::string CSyncCheckpoint::strMasterPrivKey = "";

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    std::string strMasterPubKey = TestNet() ? CSyncCheckpoint::strTestPubKey : CSyncCheckpoint::strMainPubKey;
//    if (!key.Set(ParseHex(strMasterPubKey)))
//        return error("CSyncCheckpoint::CheckSignature() : SetPubKey failed");
    CPubKey key(ParseHex(strMasterPubKey));
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// ppcoin: process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{   
    if (!CheckSignature())
        return false;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        LogPrintf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            // pfrom->PushGetBlocks(pindexBest, hashCheckpoint);
            PushGetBlocks(pfrom, chainActive.Tip(), hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocksSyncCheckpoint.count(hashCheckpoint)? Checkpoints::WantedByOrphan(mapOrphanBlocksSyncCheckpoint[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (!Checkpoints::ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CBlockIndex* pindexCheckpoint = mapBlockIndex[hashCheckpoint];
    if (!pindexCheckpoint->IsInMainChain())
    {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (!ReadBlockFromDisk(block, pindexCheckpoint))
            return error("ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        CValidationState state;
        LogPrintf("ProcessSyncCheckpoint: ConnectTip\n");
        // if (!SetBestChain(state, pindexCheckpoint))
        if (!ConnectTip(state, pindexCheckpoint))
        {
            Checkpoints::hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }

    if (!Checkpoints::WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    
    LogPrintf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
