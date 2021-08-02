// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "util.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <assert.h>

#include "chainparamsseeds.h"

std::string CDNSSeedData::getHost(uint64_t requiredServiceBits) const {
    //use default host for non-filter-capable seeds or if we use the default service bits (NODE_NETWORK)
    if (!supportsServiceBitsFiltering || requiredServiceBits == NODE_NETWORK)
        return host;

    return strprintf("x%x.%s", requiredServiceBits, host);
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, CScript genesisOutputScript, uint32_t nTime=1231006505, uint32_t nNonce=2083236893, uint32_t nBits=0x1d00ffff, int32_t nVersion=1, const CAmount& genesisReward=50 * COIN)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime=1390262400, uint32_t nNonce=13562315, uint32_t nBits=0x1e0fffff, int32_t nVersion=112, const CAmount& genesisReward=1 * COIN)
{
    const char* pszTimestamp = "Shueisha Reveals Winners of Shonen Jump Manga Contest";
    CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 120960;
        consensus.nMajorityEnforceBlockUpgrade = 7500;
        consensus.nMajorityRejectBlockOutdated = 9000;
        consensus.nMajorityWindow = 10000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 240; // 40 minutes
        consensus.nPowTargetSpacing = 30; // 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("00000000000000000000000000000000000000000000000000a90032a15bcd81");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000001967a3b6a95c9265e7250f748044fea9e0c446befdebdd064c966eeba"); // 7000000

        consensus.nRuleChangeActivationThreshold = 76; // 95% of
        consensus.nMinerConfirmationWindow = 80; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 24;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1638316800; // Dec 1st, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT; // May 1st, 2062

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1646092800; // Mar 1st, 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT; // May 1st, 2062

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
        nDelayGetHeadersTime = 24 * 60 * 60;
        nMinerThreads = 0;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock();

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000099acc274b7b403a828238bad69414e03a1a51b297a250c0a0da8a337840"));
        assert(genesis.hashMerkleRoot == uint256S("0x448f7de5e3a564ad723ea1ac11186466e35c9315acfba89d9b956b303340a7a9")); // Updated for Animecoin

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
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = CCheckpointData {
            {
                { 0,     uint256S("0x0000099acc274b7b403a828238bad69414e03a1a51b297a250c0a0da8a337840")},
                { 1,     uint256S("0x00000c3849197334206d575b9ab34ff04786ab7776ac72424ffed8dfcd3e5a5b")},
                { 1000000,     uint256S("0000000960e8582c838a435500d3b258926b99a8b891eb0f46ffa42643969c94")},
                { 2000000,     uint256S("00000035c2e947c598355205a60ed583fe5e7dee0240f8831ab9c783f47741c4")},
                { 3000000,     uint256S("00000273d7a54e6d6a00faa4c7b1472453e06b9474eeca80d28a1adce44bc1ec")},
                { 4000000,     uint256S("000000016afda82d54e7f609ab072d5e8348c28a667e9ef2206aca421ee5d813")},
                { 5000000,     uint256S("000000001c81edc9edbb1ebc1e4970b1f21131ddd9357878809a3cede21acc31")},
                { 6000000,     uint256S("00000000e24c1370993d3d2b1bc16d004e13c211936781bbdb7babe4777af790")},
                { 7000000,     uint256S("00000001967a3b6a95c9265e7250f748044fea9e0c446befdebdd064c966eeba")},
            }
        };

        chainTxData = ChainTxData {
            1604104033, // * UNIX timestamp of last checkpoint block
            7301739,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.035     // * estimated number of transactions per second after that checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.fPowAllowMinDifficultyBlocks = true;
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");
        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c");
        consensus.nRuleChangeActivationThreshold = 60; // 75% for testchains
        consensus.nMinerConfirmationWindow = 80; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 24;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1638316800; // Dec 1st, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT; // May 1st, 2062

        // Deployment of SegWit (BIP141 and BIP143)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1646092800; // Mar 1st, 2022
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT; // May 1st, 2062

        pchMessageStart[0] = 0x4d; //Updated for Animecoin
        pchMessageStart[1] = 0x49;
        pchMessageStart[2] = 0x4e;
        pchMessageStart[3] = 0x41;
        vAlertPubKey = ParseHex("04229162767c4193324ab7f78b87c8b2d539d30ecefcb2749e3afdcb54cea8c32f0b59f2b67bf97045ed0c03b1f28e01787b4ee918c5f0b50819a058cd4c6ce40e"); // Updated.
        nDefaultPort = 11212; // Contradictory.
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        nMinerThreads = 0;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 978307200; // Updated for Animecoin
        genesis.nNonce = 907185573; // Updated for Animecoin
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c")); // Updated for Animecoin

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,119); //Updated for Animecoin
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,199); //Updated for Animecoin
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,247); //Updated for Animecoin
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94}; // tprv

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = CCheckpointData {
            {
                { 0, uint256S("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c")},
            }
        };

        chainTxData = ChainTxData {
            978307200,
            1488,
            0.035
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nPowTargetTimespan = 10 * 240; // 40 minutes
        consensus.nPowTargetSpacing = 30; // 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");
        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nRuleChangeActivationThreshold = 60; // 75% for testchains
        consensus.nMinerConfirmationWindow = 80;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 24;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nMinerThreads = 1;
        genesis.nTime = 978307200;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 907185573;
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        nDelayGetHeadersTime = 0;
        // assert(hashGenesisBlock == uint256S("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = CCheckpointData {
            {
                { 0, uint256S("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c")},
            }
        };

        chainTxData = ChainTxData {
                0,
                0,
                0
        };
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
