#include <QApplication>
#include <QClipboard>
#include <string>
#include <vector>

#include "base58.h"
#include "multisiginputentry.h"
#include "ui_multisiginputentry.h"
#include "validation.h"
#include "script/script.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include "walletmodel.h"


MultisigInputEntry::MultisigInputEntry(CWallet* _pwallet, QWidget *parent) : QFrame(parent), ui(new Ui::MultisigInputEntry), model(nullptr), pwallet(_pwallet)
{
    ui->setupUi(this);
}

MultisigInputEntry::~MultisigInputEntry()
{
    delete ui;
}

void MultisigInputEntry::setModel(WalletModel* _model)
{
    this->model = _model;
    clear();
}

void MultisigInputEntry::clear()
{
    ui->contractAddress->clear();
    ui->transactionIdBox->clear();
    ui->transactionOutput->clear();
    ui->redeemScript->clear();
}

bool MultisigInputEntry::validate()
{
    return (ui->transactionOutput->count() > 0);
}

CTxIn MultisigInputEntry::getInput()
{
    int nOutput = ui->transactionOutput->currentIndex();
    CTxIn input(COutPoint(txHash, index_map[nOutput]));
    return input;
}

CAmount MultisigInputEntry::getAmount()
{
    CAmount amount = 0;
    int nOutput = ui->transactionOutput->currentIndex();
    CTransactionRef tx;
    uint256 blockHash;

    if(GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true))
    {
        if((unsigned int) index_map.value(nOutput) < tx->vout.size())
        {
            const CTxOut& txOut = tx->vout[index_map.value(nOutput)];
            amount = txOut.nValue;
        }
    }

    return amount;
}

QString MultisigInputEntry::getRedeemScript()
{
    return ui->redeemScript->text();
}

QString MultisigInputEntry::getAddress()
{
    return ui->contractAddress->text();
}

void MultisigInputEntry::setAddress(QString address)
{
     ui->contractAddress->setText(address);
     emit on_contractAddress_textChanged(address);
}

void MultisigInputEntry::setTransactionId(QString transactionId)
{
    int id = ui->transactionIdBox->findText(transactionId);
    if (id != -1)
        ui->transactionIdBox->setCurrentIndex(id);
}

void MultisigInputEntry::setTransactionOutputIndex(int index)
{
    ui->transactionOutput->setCurrentIndex(index_map.key(index));
}

void MultisigInputEntry::setRemoveEnabled(bool enabled)
{
    //ui->deleteButton->setEnabled(enabled);
}

void MultisigInputEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

void MultisigInputEntry::on_pasteRedeemScriptButton_clicked()
{
    ui->redeemScript->setText(QApplication::clipboard()->text());
}

void MultisigInputEntry::on_transactionOutput_currentIndexChanged(int index)
{
    if(ui->transactionOutput->itemText(index).isEmpty())
        return;

    CTransactionRef tx;
    uint256 blockHash;
    if(!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true))
        return;

    const CTxOut txOut = tx->vout[index_map.value(index)];

    CScript script = txOut.scriptPubKey;

    if(script.IsPayToScriptHash())
    {
        ui->redeemScript->setEnabled(true);

        if(model)
        {
            // Try to find the redeem script
            CTxDestination dest;
            if(ExtractDestination(script, dest))
                {
                    CScriptID scriptID = boost::get<CScriptID>(dest);
                    CScript redeemScript;
                    if(pwallet->GetCScript(scriptID, redeemScript))
                        ui->redeemScript->setText(HexStr(redeemScript.begin(), redeemScript.end()).c_str());
                }
        }
    }
    else
    {
        ui->redeemScript->setEnabled(false);
    }

    emit updateAmount();
}

void MultisigInputEntry::on_contractAddress_textChanged(const QString& address_input)
{
    {
        ui->transactionIdBox->clear();
        LOCK(pwallet->cs_wallet);
        for (const auto& walletEntry : pwallet->mapWallet)
        {
            QString hash = QString::fromStdString(walletEntry.first.ToString());
            const CWalletTx* tx = &walletEntry.second;

            if (!CheckFinalTx(*tx) || !tx->IsTrusted())
                continue;

            if (tx->IsCoinBase() && tx->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = tx->GetDepthInMainChain();
            if (nDepth < (tx->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            bool fitting = false;
            for (unsigned int i = 0; i < tx->tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (pwallet->IsMine(tx->tx->vout[i]) == ISMINE_WATCH_ONLY); //
                {
                    if (!ExtractDestination(tx->tx->vout[i].scriptPubKey, addr))
                        continue;
                    if (pwallet->IsSpent(walletEntry.first, i))
                        continue;
                    QString addressStr = QString::fromStdString(CBitcoinAddress(addr).ToString());
                    if (addressStr == address_input)
                    {
                        fitting = true;
                    }
                }
            }
            if (fitting)
                ui->transactionIdBox->addItem(hash);
        }
    }
}


void MultisigInputEntry::on_transactionIdBox_currentIndexChanged(const QString& transactionId)
{
    ui->transactionOutput->clear();
    if(transactionId.isEmpty())
        return;

    // Make list of transaction outputs
    txHash = uint256S(transactionId.toStdString());
    CTransactionRef tx;
    uint256 blockHash;
    if(!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true))
        return;

    index_map.clear();
    unsigned int p2sh_count = 0;
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        QString idStr;
        idStr.setNum(i);
        const CTxOut txOut = tx->vout[i];
        if (!txOut.scriptPubKey.IsPayToScriptHash())
            continue;
        index_map.insert (p2sh_count, i);
        ++p2sh_count;
        CAmount amount = txOut.nValue;
        QString amountStr = QString::fromStdString (FormatMoney(amount));
        CScript script = txOut.scriptPubKey;
        CTxDestination addr;
        if(ExtractDestination(script, addr))
        {
            CBitcoinAddress address(addr);
            QString addressStr(address.ToString().c_str());
            ui->transactionOutput->addItem(idStr + QString(" - ") + addressStr + QString(" - ") + amountStr + "ANI");
        }
        else
        {
            ui->transactionOutput->addItem(idStr + QString(" - ") + amountStr + "ANI");
        }
    }
}

