    #ifndef MULTISIGDIALOG_H
#define MULTISIGDIALOG_H

#include <QDialog>

#include "multisigaddressentry.h"
#include "multisiginputentry.h"
#include "sendcoinsentry.h"
#include "walletmodel.h"


namespace Ui
{
    class MultisigDialog;
}

class MultisigDialog : public QDialog
{
    Q_OBJECT

  public:
    explicit MultisigDialog(QWidget *parent);
    ~MultisigDialog();
    void setModel(WalletModel *model);

  public slots:
    void setAddress (const QString& address);
    MultisigAddressEntry* addPubKey();
    MultisigAddressEntry* addParty();
    MultisigAddressEntry* addHTLCParty();

    void clear();
    void updateRemoveEnabled();
    MultisigInputEntry * addInput();
    SendCoinsEntry * addOutput();

  signals:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

  private:
    Ui::MultisigDialog* ui;
    WalletModel* model;

  private slots:
    void on_createAddressButton_clicked();
    void on_createContractButton_clicked();
    void on_copyMultisigAddressButton_clicked();
    void on_copyRedeemScriptButton_clicked();
    void on_saveRedeemScriptButton_clicked();
    void on_saveMultisigAddressButton_clicked();
    void removeEntry(MultisigAddressEntry *entry);
    void on_createTransactionButton_clicked();
    void on_transaction_textChanged();
    void on_copyTransactionButton_clicked();
    void on_pasteTransactionButton_clicked();
    void on_signTransactionButton_clicked();
    void on_copySignedTransactionButton_clicked();
    void on_sendTransactionButton_clicked();
    void removeEntry(MultisigInputEntry *entry);
    void removeEntry(SendCoinsEntry *entry);
    void updateAmounts();
    void on_copyAddressButton_clicked();
    void on_copyScriptButton_clicked();
    void on_saveContractButton_clicked();
    void on_lockTimeBox_valueChanged(int arg1);
    void on_scriptEdit_textChanged();
    void on_importContractButton_clicked();
    void on_saveHTLCButton_clicked();
    void on_copyAddressButtonHTLC_clicked();
    void on_copyScriptButtonHTLC_clicked();
    void on_lockTimeBoxHTLC_valueChanged(int arg1);
    void on_createHTLCButton_clicked();
};

#endif // MULTISIGDIALOG_H
