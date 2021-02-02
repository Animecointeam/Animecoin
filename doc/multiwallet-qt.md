Multiwallet Qt Development and Integration Strategy
===================================================

In order to support loading of multiple wallets in bitcoin-qt, a few changes in the UI architecture will be needed.
Fortunately, only four of the files in the existing project are affected by this change.

Two new classes have been implemented in two new .h/.cpp file pairs, with much of the functionality that was previously
implemented in the BitcoinGUI class moved over to these new classes.

The two existing files most affected, by far, are bitcoingui.h and bitcoingui.cpp, as the BitcoinGUI class will require
some major retrofitting.

Only requiring some minor changes is bitcoin.cpp.

Finally, two new headers and source files will have to be added to bitcoin-qt.pro.

Untuk mendukung pemuatan beberapa dompet dalam bitcoin-qt, beberapa perubahan pada arsitektur UI akan dibutuhkan.
Untungnya, hanya empat file dalam proyek yang ada yang terpengaruh oleh perubahan ini.

Tiga kelas baru telah diimplementasikan dalam tiga pasang file hh. .cpp baru, dengan sebagian besar fungsi yang sebelumnya
Diimplementasikan di kelas BitcoinGUI beralih ke kelas baru ini.

Dua file yang ada paling terpengaruh, sejauh ini, adalah bitcoingui.h dan bitcoingui.cpp, karena kelas BitcoinGUI akan membutuhkan
beberapa perkuatan besar.

Hanya membutuhkan beberapa perubahan kecil adalah bitcoin.cpp.

Akhirnya, tiga header dan file sumber baru harus ditambahkan ke bitcoin-qt.pro.

Changes to class BitcoinGUI
---------------------------
The principal change to the BitcoinGUI class concerns the QStackedWidget instance called centralWidget.
This widget owns five page views: overviewPage, transactionsPage, addressBookPage, receiveCoinsPage, and sendCoinsPage.

A new class called *WalletView* inheriting from QStackedWidget has been written to handle all renderings and updates of
these page views. In addition to owning these five page views, a WalletView also has a pointer to a WalletModel instance.
This allows the construction of multiple WalletView objects, each rendering a distinct wallet.

A second class called *WalletFrame* inheriting from QFrame has been written as a container for embedding all wallet-related
controls into BitcoinGUI. At present it contains the WalletView instances for the wallets and does little more than passing on messages
from BitcoinGUI to the currently selected WalletView. It is a WalletFrame instance
that takes the place of what used to be centralWidget in BitcoinGUI. The purpose of this class is to allow future
refinements of the wallet controls with minimal need for further modifications to BitcoinGUI, thus greatly simplifying
merges while reducing the risk of breaking top-level stuff.

Perubahan utama pada kelas BitcoinGUI menyangkut instance QStackedWidget yang disebut centralWidget.
Widget ini memiliki lima tampilan halaman: overviewPage, transactionPage, addressBookPage, receiveCoinsPage, and sendCoinsPage.

Sebuah kelas baru yang disebut * WalletView * mewarisi dari QStackedWidget telah ditulis untuk menangani semua rendering dan update dari
tampilan halaman ini Selain memiliki lima tampilan halaman ini, WalletView juga memiliki pointer ke instance WalletModel.
Hal ini memungkinkan pembangunan beberapa objek WalletView, masing-masing menampilkan dompet yang berbeda.

Kelas kedua yang disebut * WalletStack *, juga mewarisi dari QStackedWidget, telah ditulis untuk menangani perpindahan fokus antara
dompet dimuat berbeda Dalam implementasinya saat ini, sebagai QStackedWidget, hanya satu dompet yang bisa dilihat sekaligus -
Tapi ini bisa diubah nanti.

Kelas ketiga yang disebut * WalletFrame * mewarisi dari QFrame telah ditulis sebagai wadah untuk menyematkan semua dompet yang terkait
kontrol ke BitcoinGUI. Saat ini hanya berisi contoh WalletStack dan tidak lebih dari sekadar menyampaikan pesan
dari BitcoinGUI ke WalletStack, yang kemudian menyerahkannya ke masing-masing WalletViews. Ini adalah contoh WalletFrame
yang mengambil tempat dari apa yang dulu menjadi pusatWidget di BitcoinGUI. Tujuan kelas ini adalah untuk memungkinkan masa depan
penyempurnaan kontrol dompet dengan kebutuhan minimal untuk modifikasi lebih lanjut pada BitcoinGUI, sehingga sangat menyederhanakannya
menggabungkan sementara mengurangi risiko melanggar barang tingkat atas.

Changes to bitcoin.cpp
----------------------
bitcoin.cpp is the entry point into bitcoin-qt, and as such, will require some minor modifications to provide hooks for
multiple wallet support. Most importantly will be the way it instantiates WalletModels and passes them to the
singleton BitcoinGUI instance called window. Formerly, BitcoinGUI kept a pointer to a single instance of a WalletModel.
The initial change required is very simple: rather than calling `window.setWalletModel(&walletModel);` we perform the
following two steps:

bitcoin.cpp adalah titik masuk ke bitcoin-qt, dan dengan demikian, akan memerlukan beberapa modifikasi kecil untuk memberikan kait untuk
beberapa dompet dukungan Yang terpenting adalah cara instantiate WalletModels dan meneruskannya ke
Singleton BitcoinGUI misalnya disebut window. Dahulu, BitcoinGUI menyimpan sebuah pointer ke satu instance dari WalletModel.
Perubahan awal yang dibutuhkan sangat sederhana: daripada memanggil `window.setWalletModel (& walletModel);` kita melakukan
berikut dua langkahnya:

	window.addWallet("~Default", &walletModel);
	window.setCurrentWallet("~Default");

The string parameter is just an arbitrary name given to the default wallet. It's been prepended with a tilde to avoid name collisions in the future with additional wallets.

Parameter string hanyalah nama sewenang-wenang yang diberikan ke dompet default. Ini sudah diimbangi dengan tilde untuk menghindari tabrakan nama di masa depan dengan dompet tambahan.

The shutdown call `window.setWalletModel(0)` has also been removed. In its place is now:

window.removeAllWallets();
