#include <QClipboard>
#include <QDateTime>
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
#include "preimagedialog.h"
#include "ui_multisigdialog.h"
#include "script/ismine.h"
#include "script/script.h"
#include "script/sign.h"
#include "sendcoinsentry.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include "wallet/rpcdump.cpp"
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
    addParty();
    addParty();
    addParty();
    addHTLCParty();
    addHTLCParty();

    ui->lockTimeBox->setMinimum (chainActive.Height());
    ui->lockTimeBox->setMaximum (std::numeric_limits<int>::max());
    ui->lockTimeBoxHTLC->setMinimum (chainActive.Height());
    ui->lockTimeBoxHTLC->setMaximum (std::numeric_limits<int>::max());

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

void MultisigDialog::setAddress (const QString& address)
{
    ui->tabWidget->setCurrentIndex(4); // Spending tab.
    MultisigInputEntry* entry = qobject_cast<MultisigInputEntry*>(ui->inputs->itemAt(0)->widget());
    if(entry)
    {
        entry->setAddress(address);
    }
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

    for(int i = 0; i < ui->partyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->partyEntries->itemAt(i)->widget());
        if(entry)
            entry->setModel(_model);
    }

    for(int i = 0; i < ui->htlcPartyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->htlcPartyEntries->itemAt(i)->widget());
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

    for(int i = 0; i < ui->partyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->partyEntries->itemAt(i)->widget());
        if(entry)
            entry->setRemoveEnabled(false);
    }

    for(int i = 0; i < ui->htlcPartyEntries->count(); i++)
    {
        MultisigAddressEntry *entry = qobject_cast<MultisigAddressEntry *>(ui->htlcPartyEntries->itemAt(i)->widget());
        if(entry)
            entry->setRemoveEnabled(false);
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
        pwalletMain->SetAddressBook(CBitcoinAddress(address).Get(), label, "watchonly");
}

void MultisigDialog::clear()
{
    while(ui->pubkeyEntries->count())
        delete ui->pubkeyEntries->takeAt(0)->widget();
    while(ui->partyEntries->count())
        delete ui->partyEntries->takeAt(0)->widget();
    while(ui->htlcPartyEntries->count())
        delete ui->htlcPartyEntries->takeAt(0)->widget();

    addPubKey();
    addPubKey();
    addParty();
    addParty();
    addParty();
    addHTLCParty();
    addHTLCParty();
    updateRemoveEnabled();
}

MultisigAddressEntry* MultisigDialog::addPubKey()
{
    MultisigAddressEntry* entry = new MultisigAddressEntry(this);

    entry->setModel(model);
    ui->pubkeyEntries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(MultisigAddressEntry*)), this, SLOT(removeEntry(MultisigAddressEntry*)));
    updateRemoveEnabled();
    entry->clear();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    return entry;
}

MultisigAddressEntry* MultisigDialog::addParty()
{
    MultisigAddressEntry *entry = new MultisigAddressEntry(this);

    entry->setModel(model);
    ui->partyEntries->addWidget(entry);
    updateRemoveEnabled();
    entry->clear();
    ui->scrollAreaWidgetContents_4->resize(ui->scrollAreaWidgetContents_4->sizeHint());
    QScrollBar* bar = ui->scrollArea_4->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    return entry;
}

MultisigAddressEntry* MultisigDialog::addHTLCParty()
{
    MultisigAddressEntry* entry = new MultisigAddressEntry(this);

    entry->setModel(model);
    ui->htlcPartyEntries->addWidget(entry);
    updateRemoveEnabled();
    entry->clear();
    ui->scrollAreaWidgetContents_5->resize(ui->scrollAreaWidgetContents_5->sizeHint());
    QScrollBar* bar = ui->scrollArea_5->verticalScrollBar();
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
        MultisigInputEntry* entry = qobject_cast<MultisigInputEntry*>(ui->inputs->itemAt(i)->widget());
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
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->outputs->itemAt(i)->widget());

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
    // TODO: we reserve extra 300 bytes for scriptsig, improve the calculation.
    size_t txSize = GetSerializeSize(transaction, SER_NETWORK, PROTOCOL_VERSION) + (300 * ui->inputs->count());
    CAmount fee = std::max (CWallet::GetRequiredFee (txSize), CWallet::fallbackFee.GetFee (txSize));

    // Calculate inputs amount
    CAmount inputsAmount = 0;
    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry* entry = qobject_cast<MultisigInputEntry*>(ui->inputs->itemAt(i)->widget());
        if(entry)
            inputsAmount += entry->getAmount();
    }

    // Calculate outputs amount
    CAmount outputsAmount = 0;
    for(int i = 0; i < ui->outputs->count(); i++)
    {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->outputs->itemAt(i)->widget());
        if(entry)
            outputsAmount += entry->getValue().amount;
    }
    if ((inputsAmount-outputsAmount)<fee)
        transaction.vout[0].nValue -= (fee-(inputsAmount-outputsAmount));

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << transaction;
    ui->transaction->setText(HexStr(ss.begin(), ss.end()).c_str());
}

void MultisigDialog::on_transaction_textChanged()
{
    // Decode the raw transaction
    std::vector<unsigned char> txData(ParseHex(ui->transaction->text().toStdString()));

    try
    {
        CDataStream ss(txData, SER_NETWORK, PROTOCOL_VERSION);
        CTransaction tx = CTransaction(deserialize, ss);

        if (tx.IsNull())
        {
            return;
        }

        // Clear the inputs and outputs
        while(ui->inputs->count())
            delete ui->inputs->takeAt(0)->widget();
        while(ui->outputs->count())
            delete ui->outputs->takeAt(0)->widget();

        if(ui->transaction->text().size() > 0)
            ui->signTransactionButton->setEnabled(true);
        else
            ui->signTransactionButton->setEnabled(false);

        // Fill input list
        int index = -1;
        for (const CTxIn& txin : tx.vin)
        {
            uint256 prevoutHash = txin.prevout.hash;
            addInput();
            index++;
            MultisigInputEntry* entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(index)->widget());
            if(entry)
            {
                CTransactionRef funding_tx;
                uint256 blockHash;
                if(GetTransaction(prevoutHash, funding_tx, Params().GetConsensus(), blockHash, true))
                {
                    if (!funding_tx->IsNull())
                    {
                        const CTxOut funding_out = funding_tx->vout[txin.prevout.n];
                        CScript script = funding_out.scriptPubKey;
                        if(script.IsPayToScriptHash())
                        {
                            CTxDestination dest;
                            if(ExtractDestination(script, dest))
                            {
                                QString addressStr = QString::fromStdString(CBitcoinAddress(dest).ToString());
                                entry->setAddress(addressStr);
                            }
                        }
                    }
                }
                entry->setTransactionId(QString::fromStdString (prevoutHash.GetHex()));
                entry->setTransactionOutputIndex(txin.prevout.n);
            }
        }

        // Fill output list
        index = -1;
        ui->infoLabel->setText("Destination includes: ");
        for (const CTxOut& txout : tx.vout)
        {
            CScript scriptPubKey = txout.scriptPubKey;
            CTxDestination addr;
            ExtractDestination(scriptPubKey, addr);
            CBitcoinAddress address(addr);
            if (IsMine(*pwalletMain, address.Get()) == ISMINE_SPENDABLE)
            {
                ui->infoLabel->setText(ui->infoLabel->text()+"your address ");
            }
            else
            {
                ui->infoLabel->setText(ui->infoLabel->text()+"foreign address ");
            }

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
    catch (const std::ios_base::failure&)
    {
        return;
    }

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

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, ui->transaction->text().toStdString(), true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    // Fetch previous transactions (inputs)
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mtx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }
        view.SetBackend(viewDummy); // switch back to avoid locking db/mempool too long
    }

    // Add the redeem scripts to the wallet keystore
    for(int i = 0; i < ui->inputs->count(); i++)
    {
        MultisigInputEntry* entry = qobject_cast<MultisigInputEntry *>(ui->inputs->itemAt(i)->widget());
        if(entry)
        {
            QString redeemScriptStr = entry->getRedeemScript();
            if(redeemScriptStr.size() > 0)
            {
                std::vector<unsigned char> scriptData(ParseHex(redeemScriptStr.toStdString()));
                CScript redeemScript(scriptData.begin(), scriptData.end());
                pwalletMain->AddCScript(redeemScript);

                // Solve script
                txnouttype whichType;
                std::vector<std::vector<unsigned char> > vSolutions;
                if (Solver(redeemScript, whichType, vSolutions))
                {
                    // HTLC secret code
                    if (whichType == TX_HTLC)
                    {
                        std::vector<unsigned char> image(vSolutions[0]);
                        std::string imghex = HexStr (image.begin(), image.end());
                        std::vector<unsigned char> preimage;

                        if (!pwalletMain->GetPreimage(image, preimage))
                        {
                            // Preimage might already be in memory. If it isn't, ask interactively.
                            PreimageDialog pd (this, imghex);
                            if (pd.exec() == QDialog::Rejected)
                                return;
                        }
                    }
                }
            }
        }
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
        return;

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mtx);

    // Sign what we can
    bool fComplete = true;
    bool route = !ui->refundCheckBox->isChecked();
    ScriptError serror = SCRIPT_ERR_OK;

    for (unsigned int i = 0; i < mtx.vin.size(); i++)
    {
        CTxIn& txin = mtx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent())
        {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coin.out.scriptPubKey;
        const CAmount& amount = coin.out.nValue;

        SignatureData sigdata;
        ProduceSignature(MutableTransactionSignatureCreator(pwalletMain, &mtx, i, amount, SIGHASH_ALL), prevPubKey, sigdata, route);
        sigdata = CombineSignatures(prevPubKey, TransactionSignatureChecker(&txConst, i, amount), sigdata, DataFromTransaction(mtx, i), route);

        UpdateTransaction(mtx, i, sigdata);

        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount), &serror))
        {
          fComplete = false;
        }
    }

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mtx;
    ui->signedTransaction->setText(HexStr(ssTx.begin(), ssTx.end()).c_str());

    if(fComplete)
    {
        ui->statusLabel->setText(tr("Transaction is ready to be sent!"));
        ui->sendTransactionButton->setEnabled(true);
    }
    else
    {
        QString error_message;
        if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
            error_message = tr("More signatures required.");
        } else if (serror == SCRIPT_ERR_OK) {
            error_message = tr("Funds already spent.");
        } else {
            error_message = QString(ScriptErrorString(serror));
        }
        ui->statusLabel->setText(tr("Transaction is NOT ready: ")+error_message);
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
    CTransactionRef ptx;
    ssData >> ptx;
    const CTransaction& tx = *ptx;
    if (tx.IsNull())
    {
        return;
    }
    uint256 txHash = tx.GetHash();

    // Check if the transaction is already in the blockchain
    CTransactionRef existingTx;
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
    if (!AcceptToMemoryPool(mempool, state, ptx, false, &fMissingInputs, nullptr, false, nMaxRawTxFee))
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

    if(!g_connman)
    {
        emit message(tr("Send Raw Transaction"), tr("Network is unreachable!"), CClientUIInterface::MSG_ERROR);
        return;
    }

    // Success, broadcast the transaction
    CInv inv(MSG_TX, tx.GetHash());
    g_connman->ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });

    MultisigInputEntry* old_entry = qobject_cast<MultisigInputEntry*>(ui->inputs->itemAt(0)->widget());
    QString strAddress = old_entry->getAddress();

    // Clear the inputs and outputs
    while(ui->inputs->count())
        delete ui->inputs->takeAt(0)->widget();
    while(ui->outputs->count())
        delete ui->outputs->takeAt(0)->widget();

    auto entry = addInput();
    entry->setAddress(strAddress);
    addOutput();
    ui->transaction->clear();
    ui->signedTransaction->clear();
    ui->signTransactionButton->setDisabled(true);
    ui->sendTransactionButton->setDisabled(true);
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
        MultisigInputEntry* entry = qobject_cast<MultisigInputEntry*>(ui->inputs->itemAt(i)->widget());
        if(entry)
            inputsAmount += entry->getAmount();
    }
    QString inputsAmountStr = QString::fromStdString (FormatMoney(inputsAmount));
    ui->inputsAmount->setText(inputsAmountStr);

    // Update outputs amount
    CAmount outputsAmount = 0;
    for(int i = 0; i < ui->outputs->count(); i++)
    {
        SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(ui->outputs->itemAt(i)->widget());
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

void MultisigDialog::on_createContractButton_clicked()
{
    ui->addressLine->clear();
    ui->scriptLine->clear();

    if(!model)
        return;

    std::vector<CPubKey> pubkeys;

    printf ("%i party entries \n", ui->partyEntries->count());
    for(int i = 0; i < ui->partyEntries->count(); i++)
    {
        MultisigAddressEntry* entry = qobject_cast<MultisigAddressEntry*>(ui->partyEntries->itemAt(i)->widget());
        printf ("Entry %i\n", i);

        if(!entry)
            continue;

        if(!entry->validate())
            return;
        QString str = entry->getPubkey();
        CPubKey vchPubKey(ParseHex(str.toStdString().c_str()));
        if(!vchPubKey.IsFullyValid())
            return;
        pubkeys.push_back(vchPubKey);
    }

    if (3 != pubkeys.size())
       return;

    CScript script = GetScriptForEscrowCLTV (pubkeys, ui->lockTimeBox->value(), 0);
    CScriptID scriptID (script);
    CBitcoinAddress address(scriptID);

    ui->addressLine->setText(address.ToString().c_str());
    ui->scriptLine->setText(HexStr(script.begin(), script.end()).c_str());
}


void MultisigDialog::on_copyAddressButton_clicked()
{
    QApplication::clipboard()->setText(ui->addressLine->text());
}


void MultisigDialog::on_copyScriptButton_clicked()
{
    QApplication::clipboard()->setText(ui->scriptLine->text());
}

void MultisigDialog::on_saveContractButton_clicked()
{
    if(!model)
        return;

    std::string redeemScript = ui->scriptLine->text().toStdString();
    std::string address = ui->addressLine->text().toStdString();
    std::string label("contract");

    if(!model->validateAddress(QString(address.c_str())))
        return;

    std::vector<unsigned char> scriptData(ParseHex(redeemScript));
    CScript script(scriptData.begin(), scriptData.end());
    CScriptID scriptID (script);

    LOCK(pwalletMain->cs_wallet);
    if(!pwalletMain->HaveCScript(scriptID))
        pwalletMain->AddCScript(script);
    if(!pwalletMain->mapAddressBook.count(CBitcoinAddress(address).Get()))
    {
        CScript script = GetScriptForDestination(CBitcoinAddress(address).Get());
        ImportScript(pwalletMain, script, label, false);
        pwalletMain->SetAddressBook(CBitcoinAddress(address).Get(), label, "watchonly");
    }
}

void MultisigDialog::on_lockTimeBox_valueChanged(int arg1)
{
    qint64 estimated_seconds = (arg1-chainActive.Height()) * 30;
    qint64 current_time = QDateTime::currentSecsSinceEpoch();
    estimated_seconds+=current_time;
    QDateTime locktime = QDateTime::fromSecsSinceEpoch(estimated_seconds);
    QString locktime_text = tr("Estimated deadline: ")+locktime.toString(Qt::SystemLocaleLongDate);
    ui->approxTimeLabel->setText(locktime_text);
}

void MultisigDialog::on_scriptEdit_textChanged()
{
    if(!model)
        return;

    std::string redeemScript = ui->scriptEdit->toPlainText().toStdString();

    std::vector<unsigned char> scriptData(ParseHex(redeemScript));
    CScript script(scriptData.begin(), scriptData.end());

    txnouttype whichType;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(script, whichType, vSolutions))
    {
        ui->addressLabel_2->setText ("Address: n/a");
        ui->typeLabel->setText("This is not a valid script.");
        return;
    }

    if (whichType == TX_MULTISIG)
    {
        ui->typeLabel->setText(tr("This is a usual multisig."));
    }
    else if (whichType == TX_ESCROW_CLTV)
    {
        ui->typeLabel->setText(tr("This is an escrow contract with a deadline."));
    }
    else if (whichType == TX_HTLC)
    {
        ui->typeLabel->setText(tr("This is HTLC."));
    }
    else
    {
        ui->typeLabel->setText(tr("This script is valid but not of a standard type."));
    }
    CScriptID scriptID (script);
    CBitcoinAddress address(scriptID);

    if(!model->validateAddress(QString(address.ToString().c_str())))
        ui->addressLabel_2->setText ("Address: invalid address!");
    else
        ui->addressLabel_2->setText ("Address: " + QString::fromStdString (address.ToString ()));
}

void MultisigDialog::on_importContractButton_clicked()
{
    if(!model)
        return;

    std::string redeemScript = ui->scriptEdit->toPlainText().toStdString();
    std::string label("contract");

    std::vector<unsigned char> scriptData(ParseHex(redeemScript));
    CScript script(scriptData.begin(), scriptData.end());
    CScriptID scriptID (script);
    CBitcoinAddress address(scriptID);

    if(!model->validateAddress(QString(address.ToString().c_str())))
        return;

    LOCK(pwalletMain->cs_wallet);
    if(!pwalletMain->HaveCScript(scriptID))
        pwalletMain->AddCScript(script);
    if(!pwalletMain->mapAddressBook.count(CBitcoinAddress(address).Get()))
    {
        CScript script = GetScriptForDestination(CBitcoinAddress(address).Get());
        ImportScript(pwalletMain, script, label, false);
        pwalletMain->SetAddressBook(CBitcoinAddress(address).Get(), label, "watchonly");
    }
}

void MultisigDialog::on_saveHTLCButton_clicked()
{
    if(!model)
        return;

    std::string redeemScript = ui->scriptLineHTLC->text().toStdString();
    std::string address = ui->addressLineHTLC->text().toStdString();
    std::string label("HTLC");

    if(!model->validateAddress(QString(address.c_str())))
        return;

    std::vector<unsigned char> scriptData(ParseHex(redeemScript));
    CScript script(scriptData.begin(), scriptData.end());
    CScriptID scriptID (script);

    LOCK(pwalletMain->cs_wallet);
    if(!pwalletMain->HaveCScript(scriptID))
        pwalletMain->AddCScript(script);
    if(!pwalletMain->mapAddressBook.count(CBitcoinAddress(address).Get()))
    {
        CScript script = GetScriptForDestination(CBitcoinAddress(address).Get());
        ImportScript(pwalletMain, script, label, false);
        pwalletMain->SetAddressBook(CBitcoinAddress(address).Get(), label, "watchonly");
    }
}


void MultisigDialog::on_copyAddressButtonHTLC_clicked()
{
    QApplication::clipboard()->setText(ui->addressLineHTLC->text());
}

void MultisigDialog::on_copyScriptButtonHTLC_clicked()
{
    QApplication::clipboard()->setText(ui->scriptLineHTLC->text());
}

void MultisigDialog::on_lockTimeBoxHTLC_valueChanged(int arg1)
{
    qint64 estimated_seconds = (arg1-chainActive.Height()) * 30;
    qint64 current_time = QDateTime::currentSecsSinceEpoch();
    estimated_seconds+=current_time;
    QDateTime locktime = QDateTime::fromSecsSinceEpoch(estimated_seconds);
    QString locktime_text = tr("Estimated deadline: ")+locktime.toString(Qt::SystemLocaleLongDate);
    ui->approxTimeLabelHTLC->setText(locktime_text);
}


void MultisigDialog::on_createHTLCButton_clicked()
{
    ui->addressLineHTLC->clear();
    ui->scriptLineHTLC->clear();

    if(!model)
        return;

    std::vector<CPubKey> pubkeys;

    printf ("%i party entries \n", ui->htlcPartyEntries->count());
    for(int i = 0; i < ui->htlcPartyEntries->count(); i++)
    {
        MultisigAddressEntry* entry = qobject_cast<MultisigAddressEntry*>(ui->htlcPartyEntries->itemAt(i)->widget());
        printf ("Entry %i\n", i);

        if(!entry)
            continue;

        if(!entry->validate())
            return;
        QString str = entry->getPubkey();
        CPubKey vchPubKey(ParseHex(str.toStdString().c_str()));
        if(!vchPubKey.IsFullyValid())
            return;
        pubkeys.push_back(vchPubKey);
    }

    if (2 != pubkeys.size())
       return;

    std::string hs = ui->hashLineHTLC->text().toStdString();
    std::vector<unsigned char> image;
    opcodetype hasher;
    if (IsHex(hs))
    {
        image = ParseHex(hs);

        if (image.size() == 32)
        {
            hasher = OP_SHA256;
        }
        else if (image.size() == 20)
        {
            hasher = OP_RIPEMD160;
        }
        else
        {
            return;
        }
    }
    else
    {
       return;
    }

    CScript script = GetScriptForHTLC(pubkeys[0], pubkeys[1], image, ui->lockTimeBoxHTLC->value(), hasher, OP_CHECKLOCKTIMEVERIFY);
    CScriptID scriptID (script);
    CBitcoinAddress address(scriptID);

    ui->addressLineHTLC->setText(address.ToString().c_str());
    ui->scriptLineHTLC->setText(HexStr(script.begin(), script.end()).c_str());
}

