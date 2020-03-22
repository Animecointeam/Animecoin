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

    MainSignalsInstance(CScheduler *pscheduler) : m_schedulerClient(pscheduler) {}
};
static CMainSignals g_signals;

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
    pool.NotifyEntryRemoved.connect(boost::bind(&CMainSignals::MempoolEntryRemoved, this, _1, _2));
}

void CMainSignals::UnregisterWithMempoolSignals(CTxMemPool& pool) {
    pool.NotifyEntryRemoved.disconnect(boost::bind(&CMainSignals::MempoolEntryRemoved, this, _1, _2));
}

CMainSignals& GetMainSignals()
{
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1, _2, _3));
    g_signals.m_internals->TransactionAddedToMempool.connect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, _1, _2));
    g_signals.m_internals->BlockConnected.connect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, _1, _2, _3));
    g_signals.m_internals->BlockDisconnected.connect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, _1));
    g_signals.m_internals->TransactionRemovedFromMempool.connect(boost::bind(&CValidationInterface::TransactionRemovedFromMempool, pwalletIn, _1));
    g_signals.m_internals->FindTransaction.connect(boost::bind(&CValidationInterface::GetNonMempoolTransaction, pwalletIn, _1, _2));
    g_signals.m_internals->SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.m_internals->SetBestNVSChain.connect(boost::bind(&CValidationInterface::SetBestNVSChain, pwalletIn));
    g_signals.m_internals->Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.m_internals->Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.m_internals->BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.m_internals->ScriptForMining.connect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.m_internals->BlockFound.connect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.m_internals->UpdatedBlockHeaderTip.connect(boost::bind(&CValidationInterface::UpdatedBlockHeaderTip, pwalletIn, _1, _2));
    g_signals.m_internals->NewPoWValidBlock.connect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, _1, _2));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->UpdatedBlockHeaderTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockHeaderTip, pwalletIn, _1, _2));
    g_signals.m_internals->BlockFound.disconnect(boost::bind(&CValidationInterface::ResetRequestCount, pwalletIn, _1));
    g_signals.m_internals->ScriptForMining.disconnect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.m_internals->BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.m_internals->Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.m_internals->Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.m_internals->SetBestNVSChain.disconnect(boost::bind(&CValidationInterface::SetBestNVSChain, pwalletIn));
    g_signals.m_internals->SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.m_internals->FindTransaction.disconnect(boost::bind(&CValidationInterface::GetNonMempoolTransaction, pwalletIn, _1, _2));
    g_signals.m_internals->TransactionAddedToMempool.disconnect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, _1, _2));
    g_signals.m_internals->BlockConnected.disconnect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, _1, _2, _3));
    g_signals.m_internals->BlockDisconnected.disconnect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, _1));
    g_signals.m_internals->TransactionRemovedFromMempool.disconnect(boost::bind(&CValidationInterface::TransactionRemovedFromMempool, pwalletIn, _1));
    g_signals.m_internals->UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1, _2, _3));
    g_signals.m_internals->NewPoWValidBlock.disconnect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, _1, _2));
}

void UnregisterAllValidationInterfaces() {
    if (!g_signals.m_internals) {
        return;
    }
    g_signals.m_internals->UpdatedBlockHeaderTip.disconnect_all_slots();
    g_signals.m_internals->BlockFound.disconnect_all_slots();
    g_signals.m_internals->ScriptForMining.disconnect_all_slots();
    g_signals.m_internals->BlockChecked.disconnect_all_slots();
    g_signals.m_internals->Broadcast.disconnect_all_slots();
    g_signals.m_internals->Inventory.disconnect_all_slots();
    g_signals.m_internals->SetBestNVSChain.disconnect_all_slots();
    g_signals.m_internals->SetBestChain.disconnect_all_slots();
    g_signals.m_internals->TransactionAddedToMempool.disconnect_all_slots();
    g_signals.m_internals->BlockConnected.disconnect_all_slots();
    g_signals.m_internals->BlockDisconnected.disconnect_all_slots();
    g_signals.m_internals->TransactionRemovedFromMempool.disconnect_all_slots();
    g_signals.m_internals->FindTransaction.disconnect_all_slots();
    g_signals.m_internals->UpdatedBlockTip.disconnect_all_slots();
    g_signals.m_internals->NewPoWValidBlock.disconnect_all_slots();
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