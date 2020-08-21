// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include <config/bitcoin-config.h>
#endif

#include "walletmodeltransaction.h"

#include "wallet/wallet.h"

WalletModelTransaction::WalletModelTransaction(const QList<SendCoinsRecipient> &_recipients) :
    recipients(_recipients),
	walletTransaction(0),
	keyChange(0),
	fee(0)
{
	walletTransaction = new CWalletTx();
}

WalletModelTransaction::~WalletModelTransaction()
{
	delete keyChange;
	delete walletTransaction;
}

QList<SendCoinsRecipient> WalletModelTransaction::getRecipients() const
{
	return recipients;
}

CWalletTx *WalletModelTransaction::getTransaction() const
{
	return walletTransaction;
}

unsigned int WalletModelTransaction::getTransactionSize()
{
    return (!walletTransaction ? 0 : (::GetSerializeSize(*(CTransaction*)walletTransaction, SER_NETWORK, PROTOCOL_VERSION)));
}

CAmount WalletModelTransaction::getTransactionFee() const
{
	return fee;
}

void WalletModelTransaction::setTransactionFee(const CAmount& newFee)
{
	fee = newFee;
}

void WalletModelTransaction::reassignAmounts(int nChangePosRet)
{
    int i = 0;
    for (QList<SendCoinsRecipient>::iterator it = recipients.begin(); it != recipients.end(); ++it)
    {
        SendCoinsRecipient& rcp = (*it);
        {
            if (i == nChangePosRet)
                i++;
            rcp.amount = walletTransaction->vout[i].nValue;
            i++;
        }
    }
}

CAmount WalletModelTransaction::getTotalTransactionAmount() const
{
    CAmount totalTransactionAmount = 0;
    foreach(const SendCoinsRecipient &rcp, recipients)
	{
		totalTransactionAmount += rcp.amount;
	}
	return totalTransactionAmount;
}

void WalletModelTransaction::newPossibleKeyChange(CWallet *wallet)
{
	keyChange = new CReserveKey(wallet);
}

CReserveKey *WalletModelTransaction::getPossibleKeyChange()
{
	return keyChange;
}