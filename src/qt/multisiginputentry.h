#ifndef MULTISIGINPUTENTRY_H
#define MULTISIGINPUTENTRY_H

#include <QFrame>
#include <QMap>

#include "amount.h"
#include "uint256.h"
#include "wallet/wallet.h"

class CTxIn;
class WalletModel;

namespace Ui
{
    class MultisigInputEntry;
}

class MultisigInputEntry : public QFrame
{
    Q_OBJECT

  public:
    explicit MultisigInputEntry(CWallet* _pwallet, QWidget *parent = 0);
    ~MultisigInputEntry();
    void setModel(WalletModel* model);
    bool validate();
    CTxIn getInput();
    CAmount getAmount();
    QString getAddress();
    QString getRedeemScript();
    void setAddress(QString address);
    void setTransactionId(QString transactionId);
    void setTransactionOutputIndex(int index);

  public slots:
    void setRemoveEnabled(bool enabled);
    void clear();

  signals:
    void removeEntry(MultisigInputEntry *entry);
    void updateAmount();

  private:
    Ui::MultisigInputEntry* ui;
    CWallet* pwallet;
    WalletModel* model;
    uint256 txHash;
    QMap <unsigned int, unsigned int> index_map;

  private slots:
    void on_deleteButton_clicked();
    void on_transactionOutput_currentIndexChanged(int index);
    void on_pasteRedeemScriptButton_clicked();
    void on_contractAddress_textChanged(const QString& address_input);
    void on_transactionIdBox_currentIndexChanged(const QString& transactionId);
};

#endif // MULTISIGINPUTENTRY_H
