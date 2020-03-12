// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <memory>

#include "primitives/transaction.h" // CTransaction(Ref)

class CBlock;
class CBlockIndex;
class CBlockLocator;
class CConnman;
class CReserveScript;
class CValidationInterface;
class CValidationState;
class uint256;
class CScheduler;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();

class CValidationInterface {
protected:
    /** Notifies listeners of updated block chain tip */
    virtual void UpdatedBlockTip (const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {}
    /** Notifies listeners of a transaction having been added to mempool. */
    virtual void TransactionAddedToMempool(const CTransactionRef &ptxn, bool validated = true) {}
    /**
     * Notifies listeners of a block being connected.
     * Provides a vector of transactions evicted from the mempool as a result.
     */
    virtual void BlockConnected(const std::shared_ptr<const CBlock> &block, const CBlockIndex *pindex, const std::vector<CTransactionRef> &txnConflicted) {}
    /** Notifies listeners of a block being disconnected */
    virtual void BlockDisconnected(const std::shared_ptr<const CBlock> &block) {}
    /** Signal used to find transactions if the node has the inv-hash but not the transaction in its mempool (non-validation mode) */
    virtual void GetNonMempoolTransaction(const uint256 &hash,  std::shared_ptr<const CTransaction> &txsp) {}
    /** Notifies listeners of a new active block chain. */
    virtual void SetBestChain(const CBlockLocator &locator) {}
    /** Notifies listeners of a new non-validating block chain. */
    virtual void SetBestNVSChain() {}
    /** Notifies listeners about an inventory item being seen on the network. */
    virtual void Inventory(const uint256 &hash) {}
    /** Tells listeners to broadcast their data. */
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) {}
    /** Notifies listeners of a block validation result */
    virtual void BlockChecked(const CBlock&, const CValidationState&) {}
    virtual void GetScriptForMining(std::shared_ptr<CReserveScript>&) {}
    /** Notifies listeners that a block has been successfully mined */
    virtual void ResetRequestCount(const uint256 &hash) {}
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated yet */
    virtual void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& block) {}
    /** Best header has changed */
    virtual void UpdatedBlockHeaderTip(bool fInitialDownload, const CBlockIndex *pindexNew) {}
    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct MainSignalsInstance;
class CMainSignals {
private:
    std::unique_ptr<MainSignalsInstance> m_internals;

    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();

public:
    /** Register a CScheduler to give callbacks which should run in the background (may only be called once) */
    void RegisterBackgroundSignalScheduler(CScheduler& scheduler);
    /** Unregister a CScheduler to give callbacks which should run in the background - these callbacks will now be dropped! */
    void UnregisterBackgroundSignalScheduler();
    /** Call any remaining callbacks on the calling thread */
    void FlushBackgroundCallbacks();

    void UpdatedBlockTip(const CBlockIndex *, const CBlockIndex *, bool fInitialDownload);
    void UpdatedBlockHeaderTip(bool fInitialDownload, const CBlockIndex *);
    void TransactionAddedToMempool(const CTransactionRef &, bool valid);
    void BlockConnected(const std::shared_ptr<const CBlock> &, const CBlockIndex *pindex, const std::vector<CTransactionRef> &);
    void BlockDisconnected(const std::shared_ptr<const CBlock> &);
    void FindTransaction(const uint256 &,  std::shared_ptr<const CTransaction> &);
    void UpdatedTransaction(const uint256 &);
    void SetBestChain(const CBlockLocator &);
    void SetBestNVSChain();
    void Inventory(const uint256 &);
    void Broadcast(int64_t nBestBlockTime, CConnman* connman);
    void BlockChecked(const CBlock&, const CValidationState&);
    void ScriptForMining(std::shared_ptr<CReserveScript>&);
    void BlockFound(const uint256 &);
    void NewPoWValidBlock(const CBlockIndex *, const std::shared_ptr<const CBlock>&);
};

CMainSignals& GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H