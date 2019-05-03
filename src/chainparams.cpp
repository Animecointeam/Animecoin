// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "assert.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

#include <boost/assign/list_of.hpp>
#include <stdint.h>

using namespace boost::assign;

//
// Main network
//

unsigned int pnSeed[] =
{
    0xd5263d05, 0x6faad876, 0x233ebbbc,
    // Updated as of Apr 2019
};

static const unsigned int timeMainGenesisBlock = 1390262400;  // Updated for Animecoin
uint256 hashMainGenesisBlock("0x0000099acc274b7b403a828238bad69414e03a1a51b297a250c0a0da8a337840"); // Updated for Animecoin
static CBigNum bnMainProofOfWorkLimit(~uint256(0) >> 20);

static const int64_t nGenesisBlockRewardCoin = 1 * COIN;// Inherited by Animecoin
static const int64_t nBlockRewardStartCoin = 8192 * COIN; //Updated for Animecoin
static const int64_t nBlockRewardMinimumCoin = 8 * COIN;//Updated for Animecoin

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x41; // Updated for Animecoin
        pchMessageStart[1] = 0x4e;
        pchMessageStart[2] = 0x49;
        pchMessageStart[3] = 0x4d;
        vAlertPubKey = ParseHex("04e8ee751a975ba7e5488267b6754e9e4249214db28d74af916d34aefdd8817c1a5d57aba2cc3ce23052ff8c8bf7028819bc966ce19e1a603b73b3e0edea902ab0"); // Updated.
        nDefaultPort = 1212; // Contradictory docs. Requires online check.
        nRPCPort = 8332; // Updated for Animecoin
        bnProofOfWorkLimit = bnMainProofOfWorkLimit;
        nSubsidyHalvingInterval = 120960; // Updated for Animecoin

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        const char* pszTimestamp = "Shueisha Reveals Winners of Shonen Jump Manga Contest"; // Updated for Animecoin
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)); // Inherited by Animecoin
        txNew.vout[0].nValue = nGenesisBlockRewardCoin;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG; // Inherited by Animecoin
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 112; // Inherited by Animecoin
        genesis.nTime    = timeMainGenesisBlock;
        genesis.nBits    = bnMainProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 13562315; // Updated for Animecoin

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == hashMainGenesisBlock);
        assert(genesis.hashMerkleRoot == uint256("0x448f7de5e3a564ad723ea1ac11186466e35c9315acfba89d9b956b303340a7a9")); // Updated for Animecoin
        // Updated for Animecoin
        vSeeds.push_back(CDNSSeedData("seed.animeco.in", "seed.animeco.in"));
        //vSeeds.push_back(CDNSSeedData("91.121.8.23", "91.121.8.23"));
        //vSeeds.push_back(CDNSSeedData("62.210.151.205", "62.210.151.205"));
        //vSeeds.push_back(CDNSSeedData("222.78.67.174", "222.78.67.174"));
        //vSeeds.push_back(CDNSSeedData("5.9.158.79", "5.9.158.79"));
        //vSeeds.push_back(CDNSSeedData("186.237.174.48", "186.237.174.48"));
        //vSeeds.push_back(CDNSSeedData("82.117.232.30", "82.117.232.30"));
        //vSeeds.push_back(CDNSSeedData("151.236.22.84", "151.236.22.84"));
        //vSeeds.push_back(CDNSSeedData("158.255.208.40", "158.255.208.40"));
        //vSeeds.push_back(CDNSSeedData("151.236.15.106", "151.236.15.106"));
        //vSeeds.push_back(CDNSSeedData("91.121.8.23", "91.121.8.23"));
        //vSeeds.push_back(CDNSSeedData("213.183.56.176", "213.183.56.176"));
        //vSeeds.push_back(CDNSSeedData("151.236.13.37", "151.236.13.37"));
        //vSeeds.push_back(CDNSSeedData("115.29.49.156", "115.29.49.156"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,23); // Updated for Animecoin
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,9); // Updated for Animecoin
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,151); // Updated for Animecoin
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >(); // xpub
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >(); // xprv

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' of between one and two
            // weeks ago.
            const int64_t nOneWeek = 7*24*60*60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x4d; //Updated for Animecoin
        pchMessageStart[1] = 0x49;
        pchMessageStart[2] = 0x4e;
        pchMessageStart[3] = 0x41;
        vAlertPubKey = ParseHex("04229162767c4193324ab7f78b87c8b2d539d30ecefcb2749e3afdcb54cea8c32f0b59f2b67bf97045ed0c03b1f28e01787b4ee918c5f0b50819a058cd4c6ce40e"); // Updated.
        nDefaultPort = 11212; // Contradictory.
        nRPCPort = 18332; // Updated for Animecoin
        strDataDir = "testnet3";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 978307200; // Updated for Animecoin
        genesis.nNonce = 907185573; // Updated for Animecoin
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c")); // Updated for Animecoin

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,119); //Updated for Animecoin
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,199); //Updated for Animecoin
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,247); //Updated for Animecoin
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >(); // tpub
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >(); // tprv
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test - new set of parameters
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 978307200;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 907185573;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";
        assert(hashGenesisBlock == uint256("0x0000042d48638031294f0d84a027e895c1a321612dc326e6adc7a6c07deb352c"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}