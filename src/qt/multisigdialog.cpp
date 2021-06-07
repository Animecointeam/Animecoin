#include <QClipboard>
#include <QDialog>
#include <QMessageBox>
#include <QScrollBar>
#include <vector>

#include "addresstablemodel.h"
#include "base58.h"
#include "consensus/validation.h"
#include "key.h"
#include "net_processing.h" // For fAutoRequestBlocks, I know it's gross.
#include "validation.h"
#include "multisigaddressentry.h"
#include "multisiginputentry.h"
#include "multisigdialog.h"
#include "policy/policy.h"
#include "ui_multisigdialog.h"
#include "script/script.h"
#include "script/sign.h"
#include "sendcoinsentry.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include "walletmodel.h"


MultisigDialog::MultisigDialog(QWidget *parent) : QDialog(parent), ui(new Ui::MultisigDialog), model(0)
{
    ui->setupUi(this);

#ifdef Q_WS_MAC // Icons on push buttons are very uncommon on Mac
    ui->addPubKeyButton->setIcon(QIcon());
    ui->clearButton->setIcon(QIcon());
    ui->addInputButton->setIcon(QIcon());
    ui->addOutputButton->setIcon(QIcon());
    ui->signTransactionButton->setIcon(QIcon());
    ui->sendTransactionButton->setIcon(QIcon());
#endif

    addPubKey();
    addPubKey();

    connect(ui->addPubKeyButton, SIGNAL(clicked()), this, SLOT(addPubKey()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    addInput();
    addOutput();
    updateAmounts();

    connect(ui->addInputButton, SIGNAL(clicked()), this, SLOT(addInput()));
    connect(ui->addOutputButton, SIGNAL(clicked()), this, SLOT(addOutput()));

    ui->signTransactionButton->setEnabled(false);
    ui->sendTransactionButton->setEnabled(false);

    if (!fAutoRequestBlocks)
    {
        ui->statusLabel->setText(tr("Spending multisig is only available to full nodes now, sorry"));
        ui->tabSpendFunds->setEnabled (false);
    }
}

MultisigDialog::~MultisigDialog()
{
    delete ui;
}

void MultisigDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    for(int i = 0; i < ui->pubkeyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->pubkeyEntries->itemAt(i)->widget());
        if(entry)
            entry->setModel(_model);
    }


    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry *entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(i)->widget());
        if(entry)
            entry->setModel(_model);
    }


    for(int i = 0; i < ui->outputs->count(); i++)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->outputs->itemAt(i)->widget());
        if(entry)
            entry->setModel(_model);
    }
}

void MultisigDialog::updateRemoveEnabled()
{
    bool enabled = (ui->pubkeyEntries->count() > 2);

    for(int i = 0; i < ui->pubkeyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->pubkeyEntries->itemAt(i)->widget());
        if(entry)
            entry->setRemoveEnabled(enabled);
    }

    QString maxSigsStr;
    maxSigsStr.setNum(ui->pubkeyEntries->count());
    ui->maxSignaturesLabel->setText(QString("/ ") + maxSigsStr);


    enabled = (ui->inputs->count() > 1);
    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry *entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(i)->widget());
        if(entry)
            entry->setRemoveEnabled(enabled);
    }

    /*
    enabled = (ui->outputs->count() > 1);
    for(int i = 0; i < ui->outputs->count(); i++)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->outputs->itemAt(i)->widget());
        if(entry)
            entry->setRemoveEnabled(enabled);
    }
    */
}

void MultisigDialog::on_createAddressButton_clicked()
{
    ui->multisigAddress->clear();
    ui->redeemScript->clear();

    if(!model)
        return;

    std::vector<CPubKey> pubkeys;
    unsigned int required = ui->requiredSignatures->text().toUInt();

    for(int i = 0; i < ui->pubkeyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->pubkeyEntries->itemAt(i)->widget());
        if(!entry->validate())
            return;
        QString str = entry->getPubkey();
        CPubKey vchPubKey(ParseHex(str.toStdString().c_str()));
        if(!vchPubKey.IsFullyValid())
            return;
        pubkeys.push_back(vchPubKey);
    }

    if((required == 0) || (required > pubkeys.size()))
       return;

    CScript script = GetScriptForMultisig (required, pubkeys);
    CScriptID scriptID (script);
    CBitcoinAddress address(scriptID);

    ui->multisigAddress->setText(address.ToString().c_str());
    ui->redeemScript->setText(HexStr(script.begin(), script.end()).c_str());
}

void MultisigDialog::on_copyMultisigAddressButton_clicked()
{
    QApplication::clipboard()->setText(ui->multisigAddress->text());
}

void MultisigDialog::on_copyRedeemScriptButton_clicked()
{
    QApplication::clipboard()->setText(ui->redeemScript->text());
}

void MultisigDialog::on_saveRedeemScriptButton_clicked()
{
    if(!model)
        return;

    std::string redeemScript = ui->redeemScript->text().toStdString();
    std::vector<unsigned char> scriptData(ParseHex(redeemScript));
    CScript script(scriptData.begin(), scriptData.end());
    CScriptID scriptID (script);

    LOCK(pwalletMain->cs_wallet);
    if(!pwalletMain->HaveCScript(scriptID))
        pwalletMain->AddCScript(script);
}

void MultisigDialog::on_saveMultisigAddressButton_clicked()
{
    if(!model)
        return;

    std::string redeemScript = ui->redeemScript->text().toStdString();
    std::string address = ui->multisigAddress->text().toStdString();
    std::string label("multisig");

    if(!model->validateAddress(QString(address.c_str())))
        return;

    std::vector<unsigned char> scriptData(ParseHex(redeemScript));
    CScript script(scriptData.begin(), scriptData.end());
    CScriptID scriptID (script);

    LOCK(pwalletMain->cs_wallet);
    if(!pwalletMain->HaveCScript(scriptID))
        pwalletMain->AddCScript(script);
    if(!pwalletMain->mapAddressBook.count(CBitcoinAddress(address).Get()))
        pwalletMain->SetAddressBook(CBitcoinAddress(address).Get(), label, "send");
}

void MultisigDialog::clear()
{
    while(ui->pubkeyEntries->count())
        delete ui->pubkeyEntries->takeAt(0)->widget();

    addPubKey();
    addPubKey();
    updateRemoveEnabled();
}

MultisigAddressEntry * MultisigDialog::addPubKey()
{
    MultisigAddressEntry *entry = new MultisigAddressEntry(this);

    entry->setModel(model);
    ui->pubkeyEntries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(MultisigAddressEntry *)), this, SLOT(removeEntry(MultisigAddressEntry *)));
    updateRemoveEnabled();
    entry->clear();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    QScrollBar *bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    return entry;
}

void MultisigDialog::removeEntry(MultisigAddressEntry *entry)
{
    delete entry;
    updateRemoveEnabled();
}

void MultisigDialog::on_createTransactionButton_clicked()
{
    CMutableTransaction transaction;

    // Get inputs
    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry *entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(i)->widget());
        if(entry)
        {
            if(entry->validate())
            {
                CTxIn input = entry->getInput();
                input.nSequence = 0xfffffffe;
                transaction.vin.push_back(input);
            }
            else
                return;
        }
    }

    // Get outputs
    for(int i = 0; i < ui->outputs->count(); i++)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->outputs->itemAt(i)->widget());

        if(entry)
        {
            if(entry->validate())
            {
                SendCoinsRecipient recipient = entry->getValue();
                CBitcoinAddress address(recipient.address.toStdString());
                CScript scriptPubKey = GetScriptForDestination (address.Get());
                CAmount amount = recipient.amount;
                CTxOut output(amount, scriptPubKey);
                transaction.vout.push_back(output);
            }
            else
                return;
        }
    }
    transaction.nLockTime = chainActive.Height();
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << transaction;
    ui->transaction->setText(HexStr(ss.begin(), ss.end()).c_str());
}

void MultisigDialog::on_transaction_textChanged()
{
    while(ui->inputs->count())
        delete ui->inputs->takeAt(0)->widget();
    while(ui->outputs->count())
        delete ui->outputs->takeAt(0)->widget();

    if(ui->transaction->text().size() > 0)
        ui->signTransactionButton->setEnabled(true);
    else
        ui->signTransactionButton->setEnabled(false);

    // Decode the raw transaction
    std::vector<unsigned char> txData(ParseHex(ui->transaction->text().toStdString()));
    CDataStream ss(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try
    {
        ss >> tx;
    }
    catch(std::exception &e)
    {
        return;
    }

    // Fill input list
    int index = -1;
    for (const CTxIn& txin : tx.vin)
    {
        uint256 prevoutHash = txin.prevout.hash;
        addInput();
        index++;
        MultisigInputEntry *entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(index)->widget());
        if(entry)
        {
            entry->setTransactionId(QString::fromStdString (prevoutHash.GetHex()));
            entry->setTransactionOutputIndex(txin.prevout.n);
        }
    }

    // Fill output list
    index = -1;
    for (const CTxOut& txout : tx.vout)
    {
        CScript scriptPubKey = txout.scriptPubKey;
        CTxDestination addr;
        ExtractDestination(scriptPubKey, addr);
        CBitcoinAddress address(addr);
        SendCoinsRecipient recipient;
        recipient.address = QString(address.ToString().c_str());
        recipient.amount = txout.nValue;
        addOutput();
        index++;
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->outputs->itemAt(index)->widget());
        if(entry)
        {
            entry->setValue(recipient);
        }
    }

    updateRemoveEnabled();
}

void MultisigDialog::on_copyTransactionButton_clicked()
{
    QApplication::clipboard()->setText(ui->transaction->text());
}

void MultisigDialog::on_pasteTransactionButton_clicked()
{
    ui->transaction->setText(QApplication::clipboard()->text());
}

void MultisigDialog::on_signTransactionButton_clicked()
{
    ui->signedTransaction->clear();

    if(!model)
        return;

    // Decode the raw transaction
    std::vector<unsigned char> txData(ParseHex(ui->transaction->text().toStdString()));
    CDataStream ss(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try
    {
        ss >> tx;
    }
    catch(std::exception &e)
    {
        return;
    }
    CMutableTransaction mergedTx(tx);

    // Fetch previous transactions (inputs)
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mergedTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }
        view.SetBackend(viewDummy); // switch back to avoid locking db/mempool too long
    }

    // Add the redeem scripts to the wallet keystore
    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry *entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(i)->widget());
        if(entry)
        {
            QString redeemScriptStr = entry->getRedeemScript();
            if(redeemScriptStr.size() > 0)
            {
                std::vector<unsigned char> scriptData(ParseHex(redeemScriptStr.toStdString()));
                CScript redeemScript(scriptData.begin(), scriptData.end());
                pwalletMain->AddCScript(redeemScript);
            }
        }
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
        return;

    // Sign what we can
    bool fComplete = true;
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent())
        {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        txin.scriptSig.clear();
        SignSignature(*pwalletMain, prevPubKey, mergedTx, i, SIGHASH_ALL);
        txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, tx.vin[i].scriptSig);
        if(!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&mergedTx, i)))
        {
          fComplete = false;
        }
    }

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
    ui->signedTransaction->setText(HexStr(ssTx.begin(), ssTx.end()).c_str());

    if(fComplete)
    {
        ui->statusLabel->setText(tr("Transaction signature is complete"));
        ui->sendTransactionButton->setEnabled(true);
    }
    else
    {
        ui->statusLabel->setText(tr("Transaction is NOT completely signed"));
        ui->sendTransactionButton->setEnabled(false);
    }
}

void MultisigDialog::on_copySignedTransactionButton_clicked()
{
    QApplication::clipboard()->setText(ui->signedTransaction->text());
}

void MultisigDialog::on_sendTransactionButton_clicked()
{
    CAmount transactionSize = ui->signedTransaction->text().size() / 2;
    if(transactionSize == 0)
        return;

    CAmount nMaxRawTxFee = maxTxFee;

    // Decode the raw transaction
    std::vector<unsigned char> txData(ParseHex(ui->signedTransaction->text().toStdString()));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try
    {
        ssData >> tx;
    }
    catch(std::exception &e)
    {
        return;
    }
    uint256 txHash = tx.GetHash();

    // Check if the transaction is already in the blockchain
    CTransaction existingTx;
    uint256 blockHash;
    if(GetTransaction(txHash, existingTx, Params().GetConsensus(), blockHash))
    {
        if(!blockHash.IsNull())
        {
            emit message(tr("Send Raw Transaction"), tr("This transaction is already in blockchain."), CClientUIInterface::MSG_ERROR);
            return;
        }
    }

    // Send the transaction to the local node
    bool fMissingInputs;
    CValidationState state;
    if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, false, nMaxRawTxFee))
    {
        emit message(tr("Send Raw Transaction"), tr("Transaction rejected: ") + QString::fromStdString(state.GetRejectReason()), CClientUIInterface::MSG_ERROR);
        return;
    }
    if (state.IsInvalid())
    {
        emit message(tr("Send Raw Transaction"), tr("Invalid transaction: ") + QString::fromStdString(state.GetRejectReason()), CClientUIInterface::MSG_ERROR);
        return;
    }
    if (fMissingInputs)
    {
        emit message(tr("Send Raw Transaction"), tr("Failed to find the inputs in coin database."), CClientUIInterface::MSG_ERROR);
        return;
    }
    //GetMainSignals().SyncTransaction(tx, nullptr, CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK, true);
    if(!g_connman)
    {
        emit message(tr("Send Raw Transaction"), tr("Network is unreachable!"), CClientUIInterface::MSG_ERROR);
        return;
    }
    CInv inv(MSG_TX, tx.GetHash());
    g_connman->ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });
}

MultisigInputEntry * MultisigDialog::addInput()
{
    MultisigInputEntry *entry = new MultisigInputEntry(this);

    entry->setModel(model);
    ui->inputs->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(MultisigInputEntry *)), this, SLOT(removeEntry(MultisigInputEntry *)));
    connect(entry, SIGNAL(updateAmount()), this, SLOT(updateAmounts()));
    updateRemoveEnabled();
    entry->clear();
    ui->scrollAreaWidgetContents_2->resize(ui->scrollAreaWidgetContents_2->sizeHint());
    QScrollBar *bar = ui->scrollArea_2->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    return entry;
}

void MultisigDialog::removeEntry(MultisigInputEntry *entry)
{
    delete entry;
    updateRemoveEnabled();
}

SendCoinsEntry * MultisigDialog::addOutput()
{
    SendCoinsEntry *entry = new SendCoinsEntry(this);

    entry->setModel(model);
    ui->outputs->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(SendCoinsEntry *)), this, SLOT(removeEntry(SendCoinsEntry *)));
    connect(entry, SIGNAL(payAmountChanged()), this, SLOT(updateAmounts()));
    updateRemoveEnabled();
    entry->clear();
    ui->scrollAreaWidgetContents_3->resize(ui->scrollAreaWidgetContents_3->sizeHint());
    QScrollBar *bar = ui->scrollArea_3->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    return entry;
}

void MultisigDialog::removeEntry(SendCoinsEntry *entry)
{
    delete entry;
    updateRemoveEnabled();
}

void MultisigDialog::updateAmounts()
{
    // Update inputs amount
    CAmount inputsAmount = 0;
    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry *entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(i)->widget());
        if(entry)
            inputsAmount += entry->getAmount();
    }
    QString inputsAmountStr = QString::fromStdString (FormatMoney(inputsAmount));
    ui->inputsAmount->setText(inputsAmountStr);

    // Update outputs amount
    CAmount outputsAmount = 0;
    for(int i = 0; i < ui->outputs->count(); i++)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->outputs->itemAt(i)->widget());
        if(entry)
            outputsAmount += entry->getValue().amount;
    }
    QString outputsAmountStr = QString::fromStdString (FormatMoney(outputsAmount));
    ui->outputsAmount->setText(outputsAmountStr);

    // Update Fee amount
    CAmount fee = inputsAmount - outputsAmount;
    if (fee < 0)
    {
        ui->createTransactionButton->setEnabled(false);
        ui->fee->setText(tr("NaN"));
        ui->statusLabel->setText(tr("Output amount exceeds input balance!"));
    }
    else
    {
        ui->createTransactionButton->setEnabled(true);
        QString feeStr = QString::fromStdString (FormatMoney(fee));
        ui->fee->setText(feeStr);
    }
}
