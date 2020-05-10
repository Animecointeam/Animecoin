// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"
#include "init.h"
#include "scheduler.h"
#include "sync.h"
#include "txmempool.h"
#include "util.h"

#include <list>
#include <atomic>

#include <boost/signals2/signal.hpp>

struct ValidationInterfaceConnections {
    boost::signals2::scoped_connection UpdatedBlockTip;
    boost::signals2::scoped_connection TransactionAddedToMempool;
    boost::signals2::scoped_connection BlockConnected;
    boost::signals2::scoped_connection BlockDisconnected;
    boost::signals2::scoped_connection TransactionRemovedFromMempool;
    boost::signals2::scoped_connection FindTransaction;
    boost::signals2::scoped_connection SetBestChain;
    boost::signals2::scoped_connection SetBestNVSChain;
    boost::signals2::scoped_connection Inventory;
    boost::signals2::scoped_connection Broadcast;
    boost::signals2::scoped_connection BlockChecked;
    boost::signals2::scoped_connection ScriptForMining;
    boost::signals2::scoped_connection BlockFound;
    boost::signals2::scoped_connection UpdatedBlockHeaderTip;
    boost::signals2::scoped_connection NewPoWValidBlock;
};

struct MainSignalsInstance {
    boost::signals2::signal<void (const CBlockIndex *, const CBlockIndex *, bool fInitialDownload)> UpdatedBlockTip;
    boost::signals2::signal<void (const CTransactionRef &, bool valid)> TransactionAddedToMempool;
    boost::signals2::signal<void (const std::shared_ptr<const CBlock> &, const CBlockIndex *pindex, const std::vector<CTransactionRef>&)> BlockConnected;
    boost::signals2::signal<void (const std::shared_ptr<const CBlock> &)> BlockDisconnected;
    boost::signals2::signal<void (const CTransactionRef &)> TransactionRemovedFromMempool;
    boost::signals2::signal<void (const uint256 &, std::shared_ptr<const CTransaction> &)> FindTransaction;
    boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
    boost::signals2::signal<void ()> SetBestNVSChain;
    boost::signals2::signal<void (const uint256 &)> Inventory;
    boost::signals2::signal<void (int64_t nBestBlockTime, CConnman* connman)> Broadcast;
    boost::signals2::signal<void (const CBlock&, const CValidationState&)> BlockChecked;
    boost::signals2::signal<void (std::shared_ptr<CReserveScript>&)> ScriptForMining;
    boost::signals2::signal<void (const uint256 &)> BlockFound;
    boost::signals2::signal<void (bool fInitialDownload, const CBlockIndex *)> UpdatedBlockHeaderTip;
    boost::signals2::signal<void (const CBlockIndex *, const std::shared_ptr<const CBlock>&)> NewPoWValidBlock;

    // We are not allowed to assume the scheduler only runs in one thread,
    // but must ensure all callbacks happen in-order, so we end up creating
    // our own queue here :(
    SingleThreadedSchedulerClient m_schedulerClient;
    std::unordered_map<CValidationInterface*, ValidationInterfaceConnections> m_connMainSignals;

    MainSignalsInstance(CScheduler *pscheduler) : m_schedulerClient(pscheduler) {}
};
static CMainSignals g_signals;

// This map has to a separate global instead of a member of MainSignalsInstance,
// because RegisterWithMempoolSignals is currently called before RegisterBackgroundSignalScheduler,
// so MainSignalsInstance hasn't been created yet.
static std::unordered_map<CTxMemPool*, boost::signals2::scoped_connection> g_connNotifyEntryRemoved;

void CMainSignals::RegisterBackgroundSignalScheduler(CScheduler& scheduler) {
    assert(!m_internals);
    m_internals.reset(new MainSignalsInstance(&scheduler));
}

void CMainSignals::UnregisterBackgroundSignalScheduler() {
    m_internals.reset(nullptr);
}

void CMainSignals::FlushBackgroundCallbacks() {
    if (m_internals) {
        m_internals->m_schedulerClient.EmptyQueue();
    }
}

void CMainSignals::RegisterWithMempoolSignals(CTxMemPool& pool) {
    g_connNotifyEntryRemoved.emplace(&pool, pool.NotifyEntryRemoved.connect(std::bind(&CMainSignals::MempoolEntryRemoved, this, std::placeholders::_1, std::placeholders::_2)));
}

void CMainSignals::UnregisterWithMempoolSignals(CTxMemPool& pool) {
    g_connNotifyEntryRemoved.erase(&pool);
}

CMainSignals& GetMainSignals()
{
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn) {
    ValidationInterfaceConnections& conns = g_signals.m_internals->m_connMainSignals[pwalletIn];
    conns.UpdatedBlockTip = g_signals.m_internals->UpdatedBlockTip.connect(std::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    conns.TransactionAddedToMempool = g_signals.m_internals->TransactionAddedToMempool.connect(std::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, std::placeholders::_1, std::placeholders::_2));
    conns.BlockConnected = g_signals.m_internals->BlockConnected.connect(std::bind(&CValidationInterface::BlockConnected, pwalletIn, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    conns.BlockDisconnected = g_signals.m_internals->BlockDisconnected.connect(std::bind(&CValidationInterface::BlockDisconnected, pwalletIn, std::placeholders::_1));
    conns.TransactionRemovedFromMempool = g_signals.m_internals->TransactionRemovedFromMempool.connect(std::bind(&CValidationInterface::TransactionRemovedFromMempool, pwalletIn, std::placeholders::_1));
    conns.FindTransaction = g_signals.m_internals->FindTransaction.connect(std::bind(&CValidationInterface::GetNonMempoolTransaction, pwalletIn, std::placeholders::_1, std::placeholders::_2));
    conns.SetBestChain = g_signals.m_internals->SetBestChain.connect(std::bind(&CValidationInterface::SetBestChain, pwalletIn, std::placeholders::_1));
    conns.SetBestNVSChain = g_signals.m_internals->SetBestNVSChain.connect(std::bind(&CValidationInterface::SetBestNVSChain, pwalletIn));
    conns.Inventory = g_signals.m_internals->Inventory.connect(std::bind(&CValidationInterface::Inventory, pwalletIn, std::placeholders::_1));
    conns.Broadcast = g_signals.m_internals->Broadcast.connect(std::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, std::placeholders::_1, std::placeholders::_2));
    conns.BlockChecked = g_signals.m_internals->BlockChecked.connect(std::bind(&CValidationInterface::BlockChecked, pwalletIn, std::placeholders::_1, std::placeholders::_2));
    conns.ScriptForMining = g_signals.m_internals->ScriptForMining.connect(std::bind(&CValidationInterface::GetScriptForMining, pwalletIn, std::placeholders::_1));
    conns.BlockFound = g_signals.m_internals->BlockFound.connect(std::bind(&CValidationInterface::ResetRequestCount, pwalletIn, std::placeholders::_1));
    conns.UpdatedBlockHeaderTip = g_signals.m_internals->UpdatedBlockHeaderTip.connect(std::bind(&CValidationInterface::UpdatedBlockHeaderTip, pwalletIn, std::placeholders::_1, std::placeholders::_2));
    conns.NewPoWValidBlock = g_signals.m_internals->NewPoWValidBlock.connect(std::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, std::placeholders::_1, std::placeholders::_2));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->m_connMainSignals.erase(pwalletIn);
}

void UnregisterAllValidationInterfaces() {
    if (!g_signals.m_internals) {
        return;
    }
    g_signals.m_internals->m_connMainSignals.clear();
}

void CallFunctionInValidationInterfaceQueue(std::function<void ()> func) {
    g_signals.m_internals->m_schedulerClient.AddToProcessQueue(std::move(func));
}

void CMainSignals::MempoolEntryRemoved(CTransactionRef ptx, MemPoolRemovalReason reason) {
    if (reason != MemPoolRemovalReason::BLOCK && reason != MemPoolRemovalReason::CONFLICT) {
        m_internals->m_schedulerClient.AddToProcessQueue([ptx, this] {
            m_internals->TransactionRemovedFromMempool(ptx);
        });
    }
}

void CMainSignals::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {
    m_internals->m_schedulerClient.AddToProcessQueue([pindexNew, pindexFork, fInitialDownload, this] {
        m_internals->UpdatedBlockTip(pindexNew, pindexFork, fInitialDownload);
    });
}

void CMainSignals::TransactionAddedToMempool(const CTransactionRef &ptx, bool valid) {
    m_internals->m_schedulerClient.AddToProcessQueue([ptx, valid, this] {
        m_internals->TransactionAddedToMempool(ptx, valid);
    });
}

void CMainSignals::BlockConnected(const std::shared_ptr<const CBlock> &pblock, const CBlockIndex *pindex, const std::shared_ptr<const std::vector<CTransactionRef>>& pvtxConflicted) {
    m_internals->m_schedulerClient.AddToProcessQueue([pblock, pindex, pvtxConflicted, this] {
        m_internals->BlockConnected(pblock, pindex, *pvtxConflicted);
    });
}

void CMainSignals::BlockDisconnected(const std::shared_ptr<const CBlock> &pblock) {
    m_internals->m_schedulerClient.AddToProcessQueue([pblock, this] {
        m_internals->BlockDisconnected(pblock);
    });
}

void CMainSignals::FindTransaction (const uint256 &hash, std::shared_ptr<const CTransaction> &txsp){
    /*
       m_internals->m_schedulerClient.AddToProcessQueue([hash, txsp, this] {
           m_internals->FindTransaction (hash, txsp);
    });
    */
    m_internals->FindTransaction (hash, txsp);
}

void CMainSignals::SetBestChain(const CBlockLocator &locator) {
    m_internals->m_schedulerClient.AddToProcessQueue([locator, this] {
        m_internals->SetBestChain(locator);
    });
}

void CMainSignals::SetBestNVSChain(){
     m_internals->m_schedulerClient.AddToProcessQueue([this] {
         m_internals->SetBestNVSChain();
     });
}

void CMainSignals::Inventory(const uint256 &hash) {
    m_internals->m_schedulerClient.AddToProcessQueue([hash, this] {
        m_internals->Inventory(hash);
    });
}

void CMainSignals::Broadcast(int64_t nBestBlockTime, CConnman* connman) {
    m_internals->Broadcast(nBestBlockTime, connman);
}

void CMainSignals::BlockChecked(const CBlock& block, const CValidationState& state) {
    m_internals->BlockChecked(block, state);
}

void CMainSignals::ScriptForMining(std::shared_ptr<CReserveScript> &script) {
    m_internals->ScriptForMining(script);
}

void CMainSignals::BlockFound (const uint256 &hash) {
    m_internals->BlockFound(hash);
}

void CMainSignals::UpdatedBlockHeaderTip (bool fInitialDownload, const CBlockIndex *pindexNew) {
    m_internals->m_schedulerClient.AddToProcessQueue([fInitialDownload, pindexNew, this] {
        m_internals->UpdatedBlockHeaderTip (fInitialDownload, pindexNew);
    });
}

void CMainSignals::NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock> &block) {
    m_internals->NewPoWValidBlock(pindex, block);
}