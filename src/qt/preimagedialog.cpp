#include "preimagedialog.h"
#include "ui_preimagedialog.h"

#include "wallet/wallet.h"

#include <QPushButton>

PreimageDialog::PreimageDialog(QWidget* parent, std::string image) : QDialog(parent),
    ui(new Ui::PreimageDialog)
{
    ui->setupUi(this);
    image_str = image;

    ui->label->setText(tr("Enter the secret code matching the hash ") + QString::fromStdString(image));

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

    QPushButton* ok_button = ui->buttonBox->button(QDialogButtonBox::Ok);
    ok_button->setEnabled(false);
}

PreimageDialog::~PreimageDialog()
{
    delete ui;
}

void PreimageDialog::on_lineEdit_textChanged(const QString& arg1)
{
    QPushButton* ok_button = ui->buttonBox->button(QDialogButtonBox::Ok);
    ok_button->setEnabled(false);

    std::string pre_str = ui->lineEdit->text().toStdString();
    std::vector<unsigned char> preimage (pre_str.begin(), pre_str.end());

    std::vector<unsigned char> image (image_str.begin(), image_str.end());

    // SHA256 round
    {
        std::vector<unsigned char> vch(32);
        CSHA256 hash;
        hash.Write(preimage.data(), preimage.size());
        hash.Finalize(vch.data());
        std::string hashhex = HexStr (vch.begin(), vch.end());
        if (hashhex==image_str)
        {
            pwalletMain->AddPreimage(vch, preimage);
            ok_button->setEnabled(true);
        }
    }

    // RIPEMD160 round
    {
        std::vector<unsigned char> vch(20);
        CRIPEMD160 hash;
        hash.Write(preimage.data(), preimage.size());
        hash.Finalize(vch.data());
        std::string hashhex = HexStr (vch.begin(), vch.end());
        if (hashhex==image_str)
        {
            pwalletMain->AddPreimage(vch, preimage);
            ok_button->setEnabled(true);
        }
    }
}
