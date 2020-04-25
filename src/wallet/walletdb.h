// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLETDB_H
#define BITCOIN_WALLETDB_H

#include "amount.h"
#include "wallet/db.h"
#include "key.h"
#include "keystore.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

static const bool DEFAULT_FLUSHWALLET = true;

class CAccount;
class CAccountingEntry;
struct CBlockLocator;
class CKeyPool;
class CMasterKey;
class CScript;
class CWallet;
class CWalletTx;
class uint160;
class uint256;

/** Error statuses for the wallet database */
enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};

/* simple HD chain data model */
class CHDChain
{
public:
    uint32_t nExternalChainCounter;
    uint32_t nInternalChainCounter;
    CKeyID masterKeyID; //!< master key hash160

    static const int VERSION_HD_BASE        = 1;
    static const int VERSION_HD_CHAIN_SPLIT = 2;
    static const int CURRENT_VERSION        = VERSION_HD_CHAIN_SPLIT;
    int nVersion;

    CHDChain() { SetNull(); }
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nExternalChainCounter);
        READWRITE(masterKeyID);
        if (this->nVersion >= VERSION_HD_CHAIN_SPLIT)
            READWRITE(nInternalChainCounter);
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        nExternalChainCounter = 0;
        nInternalChainCounter = 0;
        masterKeyID.SetNull();
    }
};

/** Access to the wallet database */
class CKeyMetadata
{
public:
    static const int VERSION_BASIC=1;
    static const int VERSION_WITH_HDDATA=10;
    static const int CURRENT_VERSION=VERSION_WITH_HDDATA;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown
    std::string hdKeypath; //optional HD/bip32 keypath
    CKeyID hdMasterKeyID; //id of the HD masterkey used to derive this key

    CKeyMetadata()
    {
        SetNull();
    }
    CKeyMetadata(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }
    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nCreateTime);
        if (this->nVersion >= VERSION_WITH_HDDATA)
        {
            READWRITE(hdKeypath);
            READWRITE(hdMasterKeyID);
        }
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
        hdKeypath.clear();
        hdMasterKeyID.SetNull();
    }
};

/** Access to the wallet database (wallet.dat) */
class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string& strFilename, const char* pszMode = "r+", bool _fFlushOnClose = true) : CDB(strFilename, pszMode, _fFlushOnClose)
    {
    }

    CWalletDB(const CWalletDB&) = delete;
    CWalletDB& operator=(const CWalletDB&) = delete;

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(uint256 hash);

    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata &keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata &keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    bool WriteCScript(const uint160& hash, const CScript& redeemScript);

    bool WriteWatchOnly(const CScript &script, const CKeyMetadata &keymeta);
    bool EraseWatchOnly(const CScript &script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteNonValidationBestBlock(const CBlockLocator& locator);
    bool ReadNonValidationBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    /// This writes directly to the database, and will not update the CWallet's cached accounting entries!
    /// Use wallet.AddAccountingEntry instead, to write *and* update its caches.
    bool WriteAccountingEntry(const uint64_t nAccEntryNum, const CAccountingEntry& acentry);
    bool WriteAccountingEntry_Backend(const CAccountingEntry& acentry);
    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string &address, const std::string &key, const std::string &value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string &address, const std::string &key);

    CAmount GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    DBErrors LoadWallet(CWallet* pwallet);
    DBErrors FindWalletTx(std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);
    DBErrors ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);
    /* Try to (very carefully!) recover wallet database (with a possible key type filter) */
    static bool Recover(const std::string& filename, void *callbackDataIn, bool (*recoverKVcallback)(void* callbackData, CDataStream ssKey, CDataStream ssValue));
    /* Recover convenience-function to bypass the key filter callback, called when verify failes, recoveres everything */
    static bool Recover(const std::string& filename);
    /* Recover filter (used as callback), will only let keys (cryptographical keys) as KV/key-type pass through */
    static bool RecoverKeysOnlyFilter(void *callbackData, CDataStream ssKey, CDataStream ssValue);
    /* Function to determin if a certain KV/key-type is a key (cryptographical key) type */
    static bool IsKeyType(const std::string& strType);
    /* verifies the database environment */
    static bool VerifyEnvironment(const std::string& walletFile, const fs::path& dataDir, std::string& errorStr);
    /* verifies the database file */
    static bool VerifyDatabaseFile(const std::string& walletFile, const fs::path& dataDir, std::string& warningStr, std::string& errorStr);

    //! write the hdchain model (external chain child index counter)
    bool WriteHDChain(const CHDChain& chain);

    static void IncrementUpdateCounter();
    static unsigned int GetUpdateCounter();

private:
    // CWalletDB(const CWalletDB&);
    // void operator=(const CWalletDB&);
};

//! Compacts BDB state so that wallet.dat is self-contained (if there are changes)
void MaybeCompactWalletDB();

#endif // BITCOIN_WALLETDB_H