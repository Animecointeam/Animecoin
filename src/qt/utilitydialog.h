// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_UTILITYDIALOG_H
#define BITCOIN_QT_UTILITYDIALOG_H

#include <QDialog>
#include <QObject>
#include "walletmodel.h"

class BitcoinGUI;
class ClientModel;

namespace Ui {
    class AboutDialog;
    class HelpMessageDialog;
    class PaperWalletDialog;
}

/** "Paper Wallet" dialog box */
class PaperWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PaperWalletDialog(QWidget *parent);
    ~PaperWalletDialog();

    void setModel(WalletModel *model);

private:
    Ui::PaperWalletDialog *ui;
    WalletModel *model;
    static const int PAPER_WALLET_READJUST_LIMIT = 20;
    static const int PAPER_WALLET_PAGE_MARGIN = 50;

private slots:
    void on_getNewAddress_clicked();
    void on_printButton_clicked();
};

/** "About" dialog box */
class AboutDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AboutDialog(QWidget *parent);
    ~AboutDialog();

    void setModel(ClientModel *model);

public slots:
    void reject ();

private:
    Ui::AboutDialog *ui;

private slots:
    void on_buttonBox_accepted();
};

/** "Help message" dialog box */
class HelpMessageDialog : public QDialog
{
    Q_OBJECT

public:
    explicit HelpMessageDialog(QWidget *parent, bool about);
    ~HelpMessageDialog();

    void printToConsole();
    void showOrPrint();

private:
    Ui::HelpMessageDialog *ui;
    QString text;

private slots:
    void on_okButton_accepted();
};


/** "Shutdown" window */
class ShutdownWindow : public QWidget
{
    Q_OBJECT

public:
    ShutdownWindow(QWidget *parent=0, Qt::WindowFlags f=0);
    static void showShutdownWindow(BitcoinGUI *window);

protected:
    void closeEvent(QCloseEvent *event);
};

#endif // BITCOIN_QT_UTILITYDIALOG_H