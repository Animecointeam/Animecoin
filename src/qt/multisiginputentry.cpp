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


MultisigInputEntry::MultisigInputEntry(QWidget *parent) : QFrame(parent), ui(new Ui::MultisigInputEntry), model(0)
{
    ui->setupUi(this);
}

MultisigInputEntry::~MultisigInputEntry()
{
    delete ui;
}

void MultisigInputEntry::setModel(WalletModel *_model)
{
    this->model = _model;
    clear();
}

void MultisigInputEntry::clear()
{
    ui->transactionId->clear();
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
    CTxIn input(COutPoint(txHash, nOutput));

    return input;
}

CAmount MultisigInputEntry::getAmount()
{
    CAmount amount = 0;
    int nOutput = ui->transactionOutput->currentIndex();
    CTransaction tx;
    uint256 blockHash;

    if(GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true))
    {
        if((unsigned int) nOutput < tx.vout.size())
        {
            const CTxOut& txOut = tx.vout[nOutput];
            amount = txOut.nValue;
        }
    }

    return amount;
}

QString MultisigInputEntry::getRedeemScript()
{
    return ui->redeemScript->text();
}

void MultisigInputEntry::setTransactionId(QString transactionId)
{
    ui->transactionId->setText(transactionId);
}

void MultisigInputEntry::setTransactionOutputIndex(int index)
{
    ui->transactionOutput->setCurrentIndex(index);
}

void MultisigInputEntry::setRemoveEnabled(bool enabled)
{
    ui->deleteButton->setEnabled(enabled);
}

void MultisigInputEntry::on_pasteTransactionIdButton_clicked()
{
    ui->transactionId->setText(QApplication::clipboard()->text());
}

void MultisigInputEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

void MultisigInputEntry::on_pasteRedeemScriptButton_clicked()
{
    ui->redeemScript->setText(QApplication::clipboard()->text());
}

void MultisigInputEntry::on_transactionId_textChanged(const QString &transactionId)
{
    ui->transactionOutput->clear();
    if(transactionId.isEmpty())
        return;

    // Make list of transaction outputs
    txHash = uint256S(transactionId.toStdString());
    CTransaction tx;
    uint256 blockHash;
    if(!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true))
        return;

    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        QString idStr;
        idStr.setNum(i);
        const CTxOut& txOut = tx.vout[i];
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
            ui->transactionOutput->addItem(idStr + QString(" - ") + amountStr + "ANI");
    }
}

void MultisigInputEntry::on_transactionOutput_currentIndexChanged(int index)
{
    if(ui->transactionOutput->itemText(index).isEmpty())
        return;

    CTransaction tx;
    uint256 blockHash;
    if(!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true))
        return;
    const CTxOut& txOut = tx.vout[index];
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
                    if(pwalletMain->GetCScript(scriptID, redeemScript))
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