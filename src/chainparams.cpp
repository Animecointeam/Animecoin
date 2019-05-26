// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

static const unsigned int timeMainGenesisBlock = 1390262400;  // Updated for Animecoin
uint256 hashMainGenesisBlock("0x0000099acc274b7b403a828238bad69414e03a1a51b297a250c0a0da8a337840"); // Updated for Animecoin
static uint256 nMainProofOfWorkLimit(~uint256(0) >> 20);

static const int64_t nGenesisBlockRewardCoin = 1 * COIN;// Inherited by Animecoin
static const int64_t nBlockRewardStartCoin = 8192 * COIN; //Updated for Animecoin
static const int64_t nBlockRewardMinimumCoin = 8 * COIN;//Updated for Animecoin

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0,     uint256("0x0000099acc274b7b403a828238bad69414e03a1a51b297a250c0a0da8a337840"))
        ( 1,     uint256("0x00000c3849197334206d575b9ab34ff04786ab7776ac72424ffed8dfcd3e5a5b"))
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1390744420, // * UNIX timestamp of last checkpoint block
        0,    		// * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        2880.0      // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c"))
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        978307200,
        0,
        2880.0
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };


























class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 120960;
        consensus.nMajorityEnforceBlockUpgrade = 7500;
        consensus.nMajorityRejectBlockOutdated = 9000;
        consensus.nMajorityWindow = 10000;
        consensus.powLimit = nMainProofOfWorkLimit;
        consensus.nPowTargetTimespan = 10 * 240; // 40 minutes
        consensus.nPowTargetSpacing = 30; // 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x41;
        pchMessageStart[1] = 0x4e;
        pchMessageStart[2] = 0x49;
        pchMessageStart[3] = 0x4d;
        vAlertPubKey = ParseHex("04e8ee751a975ba7e5488267b6754e9e4249214db28d74af916d34aefdd8817c1a5d57aba2cc3ce23052ff8c8bf7028819bc966ce19e1a603b73b3e0edea902ab0");
        nDefaultPort = 1212;
        nMinerThreads = 0;
        nPruneAfterHeight = 100000;
        nMaxTipAge = 24 * 60 * 60;

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
         *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
         *   vMerkleTree: 4a5e1e
         */
        const char* pszTimestamp = "Shueisha Reveals Winners of Shonen Jump Manga Contest"; // Updated for Animecoin
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = nGenesisBlockRewardCoin;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG; // Inherited by Animecoin
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 112; // Inherited by Animecoin
        genesis.nTime    = timeMainGenesisBlock;
        genesis.nBits    = nMainProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 13562315; // Updated for Animecoin

        assert(genesis.hashMerkleRoot == uint256("0x448f7de5e3a564ad723ea1ac11186466e35c9315acfba89d9b956b303340a7a9"));

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == hashMainGenesisBlock);
        assert(genesis.hashMerkleRoot == uint256("0x448f7de5e3a564ad723ea1ac11186466e35c9315acfba89d9b956b303340a7a9")); // Updated for Animecoin

        // Updated for Animecoin
        vSeeds.push_back(CDNSSeedData("seed.animeco.in", "seed.animeco.in"));
        //vSeeds.push_back(CDNSSeedData("96.43.130.251", "96.43.130.251"));
        //vSeeds.push_back(CDNSSeedData("91.121.8.23", "91.121.8.23"));
        //vSeeds.push_back(CDNSSeedData("62.210.151.205", "62.210.151.205"));
        //vSeeds.push_back(CDNSSeedData("222.78.67.174", "222.78.67.174"));
        //vSeeds.push_back(CDNSSeedData("5.9.158.79", "5.9.158.79"));
        //vSeeds.push_back(CDNSSeedData("186.237.174.48", "186.237.174.48"));
        //vSeeds.push_back(CDNSSeedData("82.117.232.30", "82.117.232.30"));
        //vSeeds.push_back(CDNSSeedData("151.236.22.84", "151.236.22.84"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23); // Updated for Animecoin
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,9); // Updated for Animecoin
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,151); // Updated for Animecoin
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >(); // xpub
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >(); // xprv

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0x4d; //Updated for Animecoin
        pchMessageStart[1] = 0x49;
        pchMessageStart[2] = 0x4e;
        pchMessageStart[3] = 0x41;
        vAlertPubKey = ParseHex("04229162767c4193324ab7f78b87c8b2d539d30ecefcb2749e3afdcb54cea8c32f0b59f2b67bf97045ed0c03b1f28e01787b4ee918c5f0b50819a058cd4c6ce40e"); // Updated.
        nDefaultPort = 11212; // Contradictory.
        nPruneAfterHeight = 1000;
        nMinerThreads = 0;
        nMaxTipAge = 0x7fffffff;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 978307200; // Updated for Animecoin
        genesis.nNonce = 907185573; // Updated for Animecoin
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c")); // Updated for Animecoin

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,119); //Updated for Animecoin
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,199); //Updated for Animecoin
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,247); //Updated for Animecoin
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >(); // tpub
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >(); // tprv

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nPowTargetTimespan = 10 * 240; // 40 minutes
        consensus.nPowTargetSpacing = 30; // 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        genesis.nTime = 978307200;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 907185573;
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        //assert(hashGenesisBlock == uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        consensus.nPowTargetSpacing = 30; // 30 seconds
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        consensus.fPowAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { consensus.nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { consensus.nMajorityEnforceBlockUpgrade=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { consensus.nMajorityRejectBlockOutdated=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { consensus.nMajorityWindow=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  consensus.fPowAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
        default:
            assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}