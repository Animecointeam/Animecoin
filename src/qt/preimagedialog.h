#ifndef PREIMAGEDIALOG_H
#define PREIMAGEDIALOG_H

#include "wallet/wallet.h"

#include <QDialog>

namespace Ui {
class PreimageDialog;
}

class PreimageDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PreimageDialog(QWidget* parent, std::string image, CWallet* _pwallet);
    ~PreimageDialog();

private slots:
    void on_lineEdit_textChanged(const QString &arg1);

private:
    Ui::PreimageDialog* ui;
    std::string image_str;
    CWallet* pwallet;
};

#endif // PREIMAGEDIALOG_H
