// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include "amount.h"
#include "key.h"
#include "keystore.h"
#include "validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "ui_interface.h"
#include "validationinterface.h"
#include "script/ismine.h"
#include "wallet/crypter.h"
#include "wallet/walletdb.h"
#include "wallet/rpcwallet.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

extern CWallet* pwalletMain;

/**
 * Settings
 */
extern CFeeRate payTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool fSendFreeTransactions;
extern bool fWalletRbf;

static const unsigned int DEFAULT_KEYPOOL_SIZE = 1000;
//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 0;
//! -fallbackfee default
static const CAmount DEFAULT_FALLBACK_FEE = 100; // Should be reverted to a higher amount like 2000 in the future possibly.
//! -mintxfee default
static const CAmount DEFAULT_TRANSACTION_MINFEE = 100;
//! target minimum change amount
static const CAmount MIN_CHANGE = CENT;
//! final minimum change amount after paying for fees
static const CAmount MIN_FINAL_CHANGE = MIN_CHANGE/2;
//! Default for -spendzeroconfchange
static const bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! Default for -sendfreetransactions
static const bool DEFAULT_SEND_FREE_TRANSACTIONS = false;
//! Default for -walletrejectlongchains
static const bool DEFAULT_WALLET_REJECT_LONG_CHAINS = false;
//! -txconfirmtarget default
static const unsigned int DEFAULT_TX_CONFIRM_TARGET = 20;
//! -walletrbf default
static const bool DEFAULT_WALLET_RBF = false;
//! Largest (in bytes) free transaction we're willing to create
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000;
static const bool DEFAULT_WALLETBROADCAST = true;
static const bool DEFAULT_DISABLE_WALLET = false;

//! if set, all keys will be derived by using BIP32
static const bool DEFAULT_USE_HD_WALLET = true;

//! if set, the wallet does a full-block spv sync before continue validating the chain
static const bool DEFAULT_USE_SPV = false;
extern const char * DEFAULT_WALLET_DAT;

class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CScheduler;
class CBlockPolicyEstimator;
class CWalletTx;

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_HD = 100000, // Hierarchical key derivation after BIP32 (HD Wallet)

    FEATURE_HD_SPLIT = 100000, // Wallet with HD chain split (change outputs will use m/0'/1'/k)

    FEATURE_PRE_SPLIT_KEYPOOL = 100000, // Upgraded to HD SPLIT and can have a pre-split keypool

    FEATURE_LATEST = FEATURE_PRE_SPLIT_KEYPOOL
};


/** A key pool entry */
class CKeyPool
{
public:
    int64_t nTime;
    CPubKey vchPubKey;
    bool fInternal; // for change outputs
    bool m_pre_split; // For keys generated before keypool split upgrade

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn);

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
        if (ser_action.ForRead()) {
            try {
                READWRITE(fInternal);
            }
            catch (std::ios_base::failure&) {
                /* flag as external address if we can't read the internal boolean
                   (this will be the case for any wallet before the HD chain split version) */
                fInternal = false;
            }
            try {
                READWRITE(m_pre_split);
            }
            catch (std::ios_base::failure&) {
                /* flag as postsplit address if we can't read the m_pre_split boolean
                   (this will be the case for any wallet that upgrades to HD chain split)*/
                m_pre_split = false;
            }
        }
        else {
            READWRITE(fInternal);
            READWRITE(m_pre_split);
        }
    }
};

/** Address book data */
class CAddressBookData
{
public:
    std::string name;
    std::string purpose;

    CAddressBookData()
    {
        purpose = "unknown";
    }

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

struct CRecipient
{
    CScript scriptPubKey;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
};


typedef std::map<std::string, std::string> mapValue_t;


static inline void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n"))
    {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static inline void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx
{
private:
  /** Constant used in hashBlock to indicate tx has been abandoned */
    static const uint256 ABANDON_HASH;

public:
    CTransactionRef tx;
    uint256 hashBlock;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;
    bool fValidated;

    CMerkleTx()
    {
        SetTx(MakeTransactionRef());
        Init();
    }

    CMerkleTx(CTransactionRef arg)
    {
        SetTx(std::move(arg));
        Init();
    }

    /** Helper conversion operator to allow passing CMerkleTx where CTransaction is expected.
     *  TODO: adapt callers and remove this operator. */
    operator const CTransaction&() const { return *tx; }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg)
    {
        tx = std::move(arg);
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<uint256> vMerkleBranch; // For compatibility with older versions.
        READWRITE(tx);
        // nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlockIndex* pIndex, int posInBlock);

    /**
     * Return depth of transaction in blockchain:
     * <0  : conflicts with a transaction this deep in the blockchain
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { const CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet) > 0; }
    int GetBlocksToMaturity() const;
    bool hashUnset() const { return (hashBlock.IsNull() || hashBlock == ABANDON_HASH); }
    bool isAbandoned() const { return (hashBlock == ABANDON_HASH); }
    void setAbandoned() { hashBlock = ABANDON_HASH; }

    const uint256& GetHash() const { return tx->GetHash(); }
    bool IsCoinBase() const { return tx->IsCoinBase(); }
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    const CWallet* pwallet;

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //! time received by this node
    /**
     * Stable timestamp that never changes, and reflects the order a transaction
     * was added to the wallet. Timestamp is based on the block time for a
     * transaction added as part of a block, or else the time when the
     * transaction was received if it wasn't part of a block, with the timestamp
     * adjusted in both cases so timestamp order matches the order transactions
     * were added to the wallet. More details can be found in
     * CWallet::ComputeTimeSmart().
     */
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //! position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable bool fInMempool;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CWalletTx()
    {
        Init(nullptr);
    }

    CWalletTx(const CWallet* pwalletIn, CTransactionRef arg) : CMerkleTx(std::move(arg))
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        fInMempool = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
        fValidated = false;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        if (ser_action.ForRead())
            Init(nullptr);
        char fSpent = false;

        if (!ser_action.ForRead())
        {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);

            if (fValidated)
                mapValue["validated"] = "yes";
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //! Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead())
        {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
            fValidated = (mapValue.count("validated") && mapValue["validated"] == "yes") ? true : false;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
        mapValue.erase("validated");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fImmatureCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet *pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    const CWallet* GetWallet() const
    {
        return pwallet;
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const;
    CAmount GetCredit(const isminefilter& filter) const;
    CAmount GetImmatureCredit(bool fUseCache=true) const;
    CAmount GetAvailableCredit(bool fUseCache=true) const;
    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache=true) const;
    CAmount GetChange() const;

    void GetAmounts(std::list<COutputEntry>& listReceived,
                    std::list<COutputEntry>& listSent, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter) const;

    void GetAccountAmounts(const std::string& strAccount, CAmount& nReceived,
                           CAmount& nSent, CAmount& nFee, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    bool InMempool() const;
    bool IsTrusted() const;

    int64_t GetTxTime() const;
    int GetRequestCount() const;

    bool RelayWalletTransaction(CConnman* connman);

    /** Pass this transaction to the mempool. Fails if absolute fee exceeds absurd fee. */
    bool AcceptToMemoryPool(bool fLimitFree, CAmount nAbsurdFee, CValidationState& state);

    std::set<uint256> GetConflicts() const;
};




class COutput
{
public:
    const CWalletTx *tx;
    int i;
    int nDepth;
    bool fMaybeSpendable;
    bool fMaybeSolvable;

    COutput(const CWalletTx *txIn, int iIn, int nDepthIn, bool fSpendableIn, bool fSolvableIn)
    {
        tx = txIn; i = iIn; nDepth = nDepthIn; fMaybeSpendable = fSpendableIn; fMaybeSolvable = fSolvableIn;
    }

    std::string ToString() const;

    bool IsMature(int nBlockHeight, int64_t nBlockTime, const CKeyStore& keystore) const;
    bool IsSpendableAt(int nBlockHeight, int64_t nBlockTime, const CKeyStore& keystore) const;
    bool IsSpendableAfter(const CBlockIndex& blockindex, const CKeyStore& keystore) const;
    bool IsSolvableAt(int nBlockHeight, int64_t nBlockTime, const CKeyStore& keystore) const;
    bool IsSolvableAfter(const CBlockIndex& blockindex, const CKeyStore& keystore) const;
};




/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires=0);

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};

/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos;  //! position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead())
        {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty()))
            {
                CDataStream ss(s.GetType(), s.GetVersion());
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead())
        {
            mapValue.clear();
            if (std::string::npos != nSepPos)
            {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), s.GetType(), s.GetVersion());
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};



/**
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    static std::atomic<bool> fFlushScheduled;

    /**
     * Select a set of coins such that nValueRet >= nTargetValue and at least
     * all coins from coinControl are selected; Never select unconfirmed coins
     * if they are not ours
     */
    bool SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl *coinControl = nullptr) const;

    CWalletDB *pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;
    bool fBroadcastTransactions;

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef std::multimap<COutPoint, uint256> TxSpends;
    TxSpends mapTxSpends;
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

    /* Mark a transaction (and its in-wallet descendants) as conflicting with a particular block. */
    void MarkConflicted(const uint256& hashBlock, const uint256& hashTx);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);

    /* Used by TransactionAddedToMemorypool/BlockConnected/Disconnected */
    void SyncTransaction(const CTransaction& tx, const CBlockIndex *pindexBlockConnected, int posInBlock, bool validated);

    /* the HD chain data model (external chain counters) */
    CHDChain hdChain;

    std::set<int64_t> setInternalKeyPool;
    std::set<int64_t> setExternalKeyPool;
    std::set<int64_t> set_pre_split_keypool;
    int64_t m_max_keypool_index;
    std::map<CKeyID, int64_t> m_pool_key_to_index;
    std::atomic<bool> spvEnabled;

    int64_t nTimeFirstKey;

    /**
     * Private version of AddWatchOnly method which does not accept a
     * timestamp, and which will reset the wallet's nTimeFirstKey value to 1 if
     * the watch key did not previously have a timestamp associated with it.
     * Because this is an inherited virtual method, it is accessible despite
     * being marked private, but it is marked private anyway to encourage use
     * of the other AddWatchOnly which accepts a timestamp and sets
     * nTimeFirstKey more intelligently for more efficient rescans.
     */
    bool AddWatchOnly(const CScript& dest) override;

    /**
     * The following is used to keep track of how far behind the wallet is
     * from the chain sync, and to allow clients to block on us being caught up.
     *
     * Note that this is *not* how far we've processed, we may need some rescan
     * to have seen all transactions in the chain, but is only used to track
     * live BlockConnected callbacks.
     *
     * Protected by cs_main (see BlockUntilSyncedToCurrentChain)
     */
    const CBlockIndex* m_last_block_processed;

    /* HD derive new child key (on internal or external chain) */
    void DeriveNewChildKey(CWalletDB &walletdb, CKeyMetadata& metadata, CKey& secret, bool internal = false);

    std::unique_ptr<CWalletDBWrapper> dbw;

public:
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet.
     */
    mutable CCriticalSection cs_wallet;

    /** Get database handle used by this wallet. Ideally this function would
     * not be necessary.
     */
    CWalletDBWrapper& GetDBHandle()
    {
        return *dbw;
    }

    /** Get a name for this wallet for logging/debugging purposes.
     */
    std::string GetName() const
    {
        if (dbw) {
            return dbw->GetName();
        } else {
            return "dummy";
        }
    }

    void LoadKeyPool(int64_t nIndex, const CKeyPool &keypool);

    void MarkPreSplitKeys();

    // Map from Key ID (for regular keys) or Script ID (for watch-only keys) to
    // key metadata.
    std::map<CTxDestination, CKeyMetadata> mapKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    // Create wallet with dummy database handle
    CWallet(): dbw(new CWalletDBWrapper())
    {
        SetNull();
    }

    // Create wallet with passed-in database handle
    CWallet(std::unique_ptr<CWalletDBWrapper> dbw_in) : dbw(std::move(dbw_in))
    {
        SetNull();
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
        pwalletdbEncryption = nullptr;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = nullptr;
        nOrderPosNext = 0;
        nNextResend = 0;
        nLastResend = 0;
        m_max_keypool_index = 0;
        nTimeFirstKey = 0;
        fBroadcastTransactions = false;
        pNVSLastKnownBestHeader = nullptr;
        pNVSBestBlock = nullptr;
        spvEnabled = false;
        m_last_block_processed = nullptr;
    }

    std::map<uint256, CWalletTx> mapWallet;
    std::list<CAccountingEntry> laccentries;

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems wtxOrdered;

    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;

    std::set<COutPoint> setLockedCoins;

    //! last known best header, required to check for forks
    const CBlockIndex *pNVSLastKnownBestHeader;
    //! wallet did non-validation scan up to this block
    const CBlockIndex *pNVSBestBlock;

    const CWalletTx* GetWalletTx(const uint256& hash) const;

    std::vector<CWalletTx> getWalletTxs();

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) const { AssertLockHeld(cs_wallet); return nWalletMaxVersion >= wf; }

    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true, const CCoinControl *coinControl = nullptr, bool fIncludeZeroValue=false) const;
    /**
     * Shuffle and select coins until nTargetValue is reached while avoiding
     * small change; This method is stochastic for some inputs and upon
     * completion the coin set and corresponding actual target value is
     * assembled
     */
    bool SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, uint64_t nMaxAncestors, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const;

    bool IsSpent(const uint256& hash, unsigned int n) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(const COutPoint& output);
    void UnlockCoin(const COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);

    /**
     * keystore implementation
     * Generate a new key
     */
    CPubKey GenerateNewKey(CWalletDB& walletdb, bool internal = false);
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    bool AddKeyPubKeyWithDB(CWalletDB &walletdb,const CKey& key, const CPubKey &pubkey);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CTxDestination& pubKey, const CKeyMetadata &metadata);

    bool LoadMinVersion(int nVersion) { AssertLockHeld(cs_wallet); nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }
    void UpdateTimeFirstKey(int64_t nCreateTime);

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination &dest, const std::string &key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript& dest, int64_t nCreateTime);
    bool RemoveWatchOnly(const CScript &dest);
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);

    //! Holds a timestamp at which point the wallet is scheduled (externally) to be relocked. Caller must arrange for actual relocking to occur via Lock().
    int64_t nRelockTime;

    bool Unlock(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const;
    unsigned int ComputeTimeSmart(const CWalletTx& wtx) const;

    /**
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CWalletDB *pwalletdb = nullptr);
    DBErrors ReorderTransactions();
    bool AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment = "");
    bool GetAccountPubkey(CPubKey &pubKey, std::string strAccount, bool bForceNew = false);

    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn, bool fFlushOnClose=true);
    bool LoadToWallet(const CWalletTx& wtxIn);
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate, bool fValidated);
    void TransactionAddedToMempool(const CTransactionRef& tx, bool validated) override;
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex *pindex, const std::vector<CTransactionRef>& vtxConflicted) override;
    void BlockDisconnected(const std::shared_ptr<const CBlock>& pblock) override;
    void UpdatedBlockHeaderTip(bool fInitialDownload, const CBlockIndex *pindexNew);
    void GetNonMempoolTransaction(const uint256 &hash, CTransactionRef &txsp);
    CBlockIndex* ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    void TransactionRemovedFromMempool(const CTransactionRef &ptx) override;
    void ReacceptWalletTransactions();
    void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman);
    std::vector<uint256> ResendWalletTransactionsBefore(int64_t nTime, CConnman* connman);
    CAmount GetBalance() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;

    /**
     * Insert additional inputs into the transaction by
     * calling CreateTransaction();
     */
    bool FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, bool overrideEstimatedFeeRate, const CFeeRate& specificFeeRate, int& nChangePosInOut, std::string& strFailReason, bool includeWatching, bool lockUnspents, const CTxDestination& destChange = CNoDestination());

    /**
     * Create a new transaction paying the recipients with a set of coins
     * selected by SelectCoins(); Also create the change output, when needed
     */
    bool CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl *coinControl = nullptr, bool sign = true);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state);

    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries);
    bool AddAccountingEntry(const CAccountingEntry&);
    bool AddAccountingEntry(const CAccountingEntry&, CWalletDB *pwalletdb);

    static CFeeRate minTxFee;
    static CFeeRate fallbackFee;
    /**
     * Estimate the minimum fee considering user set parameters
     * and the required fee
     */
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool, const CBlockPolicyEstimator& estimator);
    /**
     * Return the minimum required fee taking into account the
     * floating relay fee and user set minimum transaction fee
     */
    static CAmount GetRequiredFee(unsigned int nTxBytes);
    bool NewKeyPool();
    size_t KeypoolCountExternalKeys();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex, bool fInternal, const CPubKey& pubkey);
    bool GetKeyFromPool(CPubKey &key, bool internal = false);
    int64_t GetOldestKeyPoolTime();
    /**
     * Marks all keys in the keypool up to and including reserve_key as used.
     */
    void MarkReserveKeysAsUsed(int64_t keypool_id);
    const std::map<CKeyID, int64_t>& GetAllReserveKeys() const { return m_pool_key_to_index; }

    std::set< std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    CAmount GetAccountBalance(const std::string& strAccount, int nMinDepth, const isminefilter& filter);
    CAmount GetAccountBalance(CWalletDB& walletdb, const std::string& strAccount, int nMinDepth, const isminefilter& filter);
    std::set<CTxDestination> GetAccountAddresses(const std::string& strAccount) const;

    isminetype IsMine(const CTxIn& txin) const;
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const;
    CAmount GetCredit(const CTxOut& txout, const isminefilter& filter) const;
    bool IsChange(const CTxOut& txout) const;
    CAmount GetChange(const CTxOut& txout) const;
    bool IsMine(const CTransaction& tx) const;
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const;
    CAmount GetChange(const CTransaction& tx) const;
    void SetBestChain(const CBlockLocator& loc);
    void SetBestNVSChain();

    DBErrors LoadWallet(bool& fFirstRunRet);
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);
    DBErrors ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);

    bool DelAddressBook(const CTxDestination& address);

    void Inventory(const uint256 &hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    void GetScriptForMining(std::shared_ptr<CReserveScript> &script) override;
    void ResetRequestCount(const uint256 &hash) override
    {
        LOCK(cs_wallet);
        mapRequestCount[hash] = 0;
    }

    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // set{Ex,In}ternalKeyPool
        return setInternalKeyPool.size() + setExternalKeyPool.size();
    }

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = nullptr, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion() { LOCK(cs_wallet); return nWalletVersion; }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    //! Flush wallet (bitdb flush)
    void Flush(bool shutdown=false);

    //! Verify the wallet database and perform salvage if required
    static bool Verify();

    /**
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const CTxDestination
            &address, const std::string &label, bool isMine,
            const std::string &purpose,
            ChangeType status)> NotifyAddressBookChanged;

    /**
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void (CWallet *wallet, const uint256 &hashTx,
            ChangeType status)> NotifyTransactionChanged;

    /** Show progress e.g. for rescan */
    boost::signals2::signal<void (const std::string &title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** SPV Mode changed */
    boost::signals2::signal<void (bool fSPVEnabled)> NotifySPVModeChanged;

    /** Inquire whether this wallet broadcasts transactions. */
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; }
    /** Set whether this wallet broadcasts transactions. */
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its inputs may be respent. */
    bool AbandonTransaction(const uint256& hashTx);

    /* Returns the wallets help message */
    static std::string GetWalletHelpString(bool showDebug);

    /* initializes the wallet, returns a new CWallet instance or a null pointer in case of an error */
    static CWallet* CreateWalletFromFile(const std::string walletFile);
    static bool InitLoadWallet();

    /**
     * Wallet post-init setup
     * Gives the wallet a chance to register repetitive tasks and complete post-init tasks
     */
    void postInitProcess(CScheduler& scheduler);

    /* Wallets parameter interaction */
    static bool ParameterInteraction();

    void RequestSPVScan(int64_t optional_timestamp = 0);
    void setSPVEnabled(bool status);
    bool IsSPVEnabled();

    bool BackupWallet(const std::string& strDest);

    /* Set the HD chain model (chain child index counters) */
    bool SetHDChain(const CHDChain& chain, bool memonly);
    const CHDChain& GetHDChain() { return hdChain; }

    /* Returns true if HD is enabled */
    bool IsHDEnabled();

    /* Generates a new HD master key (will not be activated) */
    CPubKey GenerateNewHDMasterKey();

    /* Derives a new HD master key (will not be activated) */
    CPubKey DeriveNewMasterHDKey(const CKey& key);

    /* Set the current HD master key (will reset the chain child index counters)
       Sets the master key's version based on the current wallet version (so the
       caller must ensure the current wallet version is correct before calling
       this function). */
    bool SetHDMasterKey(const CPubKey& key);

    /**
     * Blocks until the wallet state is up-to-date to /at least/ the current
     * chain at the time this function is entered
     * Obviously holding cs_main/cs_wallet when going into this call may cause
     * deadlock
     */
    void BlockUntilSyncedToCurrentChain();
};

/** A key allocated from the key pool. */
class CReserveKey : public CReserveScript
{
protected:
    CWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;
    bool fInternal;
public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
        fInternal = false;
    }

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey &pubkey, bool internal = false);
    void KeepKey();
    void KeepScript() override { KeepKey(); }
};

/**
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    }
};

#endif // BITCOIN_WALLET_H
