Mac OS X bitcoind build instructions
====================================

Mac OS X membuat instruksi bitcoin

Authors
-------

* Laszlo Hanyecz <solar@heliacal.net>
* Douglas Huff <dhuff@jrbobdobbs.org>
* Colin Dean <cad@cad.cx>
* Gavin Andresen <gavinandresen@gmail.com>

Penulis
-------

* Laszlo Hanyecz <solar@heliacal.net>
* Douglas Huff <dhuff@jrbobdobbs.org>
* Colin Dean <cad@cad.cx>
* Gavin Andresen <gavinandresen@gmail.com>

License
-------

Copyright (c) 2009-2012 Bitcoin Developers

Distributed under the MIT/X11 software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.

This product includes software developed by the OpenSSL Project for use in
the OpenSSL Toolkit (http://www.openssl.org/).

This product includes cryptographic software written by
Eric Young (eay@cryptsoft.com) and UPnP software written by Thomas Bernard.

Lisensi
-------

Hak Cipta (c) 2009-2012 Pengembang Bitcoin

Didistribusikan di bawah lisensi perangkat lunak MIT / X11, lihat yang menyertainya
file COPYING atau http://www.opensource.org/licenses/mit-license.php.

Produk ini mencakup perangkat lunak yang dikembangkan oleh OpenSSL Project untuk digunakan di Indonesia
OpenSSL Toolkit (http://www.openssl.org/).

Produk ini berisi perangkat lunak kriptografi yang ditulis oleh
Eric Young (eay@cryptsoft.com) dan perangkat lunak UPnP yang ditulis oleh Thomas Bernard.

Notes
-----

See `doc/readme-qt.rst` for instructions on building Bitcoin-Qt, the
graphical user interface.

Tested on OS X 10.5 through 10.8 on Intel processors only. PPC is not
supported because it is big-endian.

All of the commands should be executed in a Terminal application. The
built-in one is located in `/Applications/Utilities`.

Catatan
-----

Lihat `doc / readme-qt.rst` untuk instruksi membangun Bitcoin-Qt,
antarmuka pengguna grafis

Diuji pada OS X 10,5 sampai 10,8 pada prosesor Intel saja. PPC tidak
didukung karena bersifat big-endian.

Semua perintah harus dieksekusi dalam aplikasi Terminal. Itu
built-in satu terletak di `/ Applications / Utilities`.

Preparation
-----------

You need to install XCode with all the options checked so that the compiler
and everything is available in /usr not just /Developer. XCode should be
available on your OS X installation media, but if not, you can get the
current version from https://developer.apple.com/xcode/. If you install
Xcode 4.3 or later, you'll need to install its command line tools. This can
be done in `Xcode > Preferences > Downloads > Components` and generally must
be re-done or updated every time Xcode is updated.

There's an assumption that you already have `git` installed, as well. If
not, it's the path of least resistance to install [Github for Mac](https://mac.github.com/)
(OS X 10.7+) or
[Git for OS X](https://code.google.com/p/git-osx-installer/). It is also
available via Homebrew or MacPorts.

You will also need to install [Homebrew](http://mxcl.github.io/homebrew/)
or [MacPorts](https://www.macports.org/) in order to install library
dependencies. It's largely a religious decision which to choose, but, as of
December 2012, MacPorts is a little easier because you can just install the
dependencies immediately - no other work required. If you're unsure, read
the instructions through first in order to assess what you want to do.
Homebrew is a little more popular among those newer to OS X.

The installation of the actual dependencies is covered in the Instructions
sections below.

Persiapan
-----------

Anda perlu menginstal Xcode dengan semua pilihan yang diperiksa sehingga kompilator
dan semuanya tersedia di / usr tidak hanya / Developer. Xcode seharusnya
tersedia di media instalasi OS X Anda, tapi jika tidak, Anda bisa mendapatkan
versi sekarang dari https://developer.apple.com/xcode/ Jika Anda menginstal
Xcode 4.3 atau yang lebih baru, Anda harus menginstal tool command line-nya. Ini bisa
dilakukan di `Xcode> Preferences> Downloads> Components` dan umumnya harus
dilakukan ulang atau diperbarui setiap kali Xcode diperbarui.

Ada anggapan bahwa Anda sudah memiliki `git` terinstal juga. Jika
Bukan, ini adalah jalur yang paling tidak tahan untuk dipasang [Github for Mac] (https://mac.github.com/)
(OS X 10.7+) atau
[Git untuk OS X] (https://code.google.com/p/git-osx-installer/). Itu juga
tersedia melalui Homebrew atau MacPorts.

Anda juga perlu menginstal [Homebrew] (http://mxcl.github.io/homebrew/)
atau [MacPorts] (https://www.macports.org/) untuk menginstal perpustakaan
ketergantungan. Ini sebagian besar merupakan keputusan religius yang harus dipilih, tapi, seperti pada
Desember 2012, MacPorts sedikit lebih mudah karena Anda hanya bisa menginstal
segera dependensi - tidak ada pekerjaan lain yang diperlukan. Jika Anda tidak yakin, baca
instruksi terlebih dahulu untuk menilai apa yang ingin Anda lakukan.
Homebrew sedikit lebih populer di kalangan yang lebih baru ke OS X.

Pemasangan dependensi sebenarnya tercakup dalam Instruksi
bagian di bawah

Instructions: MacPorts
----------------------

### Install dependencies

Installing the dependencies using MacPorts is very straightforward.

    sudo port install boost db48@+no_java openssl miniupnpc
    
Petunjuk: MacPorts
----------------------

### Instal dependensi

Menginstal dependensi menggunakan MacPort sangat mudah.

     sudo port install boost db48 @ + no_java openssl miniupnpc

### Building `bitcoind`

1. Clone the github tree to get the source code and go into the directory.

        git clone git@github.com:bitcoin/bitcoin.git bitcoin
        cd bitcoin

2.  Build bitcoind:

        cd src
        make -f makefile.osx

3.  It is a good idea to build and run the unit tests, too:

        make -f makefile.osx test
        
### Membangun `bitcoind`

1. Kloning pohon github untuk mendapatkan kode sumber dan masuk ke direktori.

         git clone git@github.com: bitcoin / bitcoin.git bitcoin
         cd bitcoin

2. Bangun bitcoind:

         cd src
         make -f makefile.osx

3. Ide bagus untuk membangun dan menjalankan tes unit juga:

         make -f makefile.osx test

Instructions: HomeBrew
----------------------

#### Install dependencies using Homebrew

        brew install boost miniupnpc openssl berkeley-db4

Note: After you have installed the dependencies, you should check that the Brew installed version of OpenSSL is the one available for compilation. You can check this by typing

        openssl version

into Terminal. You should see OpenSSL 1.0.1e 11 Feb 2013.

If not, you can ensure that the Brew OpenSSL is correctly linked by running

        brew link openssl --force

Rerunning "openssl version" should now return the correct version.

Instruksi: HomeBrew
----------------------

#### Install dependencies menggunakan Homebrew

         brew install boost miniupnpc openssl berkeley-db4

Catatan: Setelah menginstal dependensi, Anda harus memeriksa apakah versi yang diinstal Brew dari OpenSSL adalah yang tersedia untuk kompilasi. Anda dapat memeriksa ini dengan mengetik

         versi openssl

ke Terminal Anda harus melihat OpenSSL 1.0.1e 11 Feb 2013.

Jika tidak, Anda dapat memastikan bahwa OpenSSL Brew terhubung dengan benar dengan berlari

         brew link openssl --force

Rerunning "versi openssl" sekarang harus mengembalikan versi yang benar.

### Building `bitcoind`

1. Clone the github tree to get the source code and go into the directory.

        git clone git@github.com:bitcoin/bitcoin.git bitcoin
        cd bitcoin

2.  Modify source in order to pick up the `openssl` library.

    Edit `makefile.osx` to account for library location differences. There's a
    diff in `contrib/homebrew/makefile.osx.patch` that shows what you need to
    change, or you can just patch by doing

        patch -p1 < contrib/homebrew/makefile.osx.patch

3.  Build bitcoind:

        cd src
        make -f makefile.osx

4.  It is a good idea to build and run the unit tests, too:

        make -f makefile.osx test
        
### Membangun `bitcoind`

1. Kloning pohon github untuk mendapatkan kode sumber dan masuk ke direktori.

         git clone git@github.com: bitcoin / bitcoin.git bitcoin
         cd bitcoin

2. Ubah sumber untuk mengambil perpustakaan `openssl`.

     Edit `makefile.osx` untuk memperhitungkan perbedaan lokasi perpustakaan. Ada
     diff di `contrib / homebrew / makefile.osx.patch` yang menunjukkan apa yang Anda butuhkan
     berubah, atau Anda hanya bisa menambal dengan melakukan

         patch -p1 <contrib / homebrew / makefile.osx.patch

3. Bangun bitcoind:

         cd src
         make -f makefile.osx

4. Ide bagus untuk membangun dan menjalankan tes unit juga:

         make -f makefile.osx test

Creating a release build
------------------------

A bitcoind binary is not included in the Bitcoin-Qt.app bundle. You can ignore
this section if you are building `bitcoind` for your own use.

If you are building `bitcoind` for others, your build machine should be set up
as follows for maximum compatibility:

All dependencies should be compiled with these flags:

    -mmacosx-version-min=10.5 -arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk

For MacPorts, that means editing your macports.conf and setting
`macosx_deployment_target` and `build_arch`:

    macosx_deployment_target=10.5
    build_arch=i386

... and then uninstalling and re-installing, or simply rebuilding, all ports.

As of December 2012, the `boost` port does not obey `macosx_deployment_target`.
Download `http://gavinandresen-bitcoin.s3.amazonaws.com/boost_macports_fix.zip`
for a fix. Some ports also seem to obey either `build_arch` or
`macosx_deployment_target`, but not both at the same time. For example, building
on an OS X 10.6 64-bit machine fails. Official release builds of Bitcoin-Qt are
compiled on an OS X 10.6 32-bit machine to workaround that problem.

Once dependencies are compiled, creating `Bitcoin-Qt.app` is easy:

    make -f Makefile.osx RELEASE=1
    
Membuat rilis build
------------------------

Biner bitcoind tidak termasuk dalam bundel Bitcoin-Qt.app. Anda bisa mengabaikannya
bagian ini jika Anda sedang membangun `bitcoind` untuk penggunaan Anda sendiri.

Jika Anda sedang membangun `bitcoind` untuk orang lain, mesin build Anda harus disiapkan
sebagai berikut untuk kompatibilitas maksimum:

Semua dependensi harus dikompilasi dengan bendera ini:

    -mmacosx-version-min = 10.5 -arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk

Untuk MacPort, itu berarti mengedit macports.conf dan setting Anda
`macosx_deployment_target` dan` build_arch`:

    macosx_deployment_target = 10.5
    build_arch = i386

... dan kemudian menguninstall dan menginstal ulang, atau hanya membangun kembali, semua port.

Per Desember 2012, port `boost` tidak mematuhi` macosx_deployment_target`.
Download `http: // gavinandresen-bitcoin.s3.amazonaws.com/ boost_macports_fix.zip`
untuk memperbaiki Beberapa port juga tampaknya mematuhi baik `build_arch` atau
`macosx_deployment_target`, tapi tidak keduanya pada saat bersamaan. Misalnya bangunan
pada mesin OS X 10.6 64-bit gagal. Rilis resmi membangun Bitcoin-Qt
dikompilasi pada mesin OS X 10.6 32-bit untuk mengatasi masalah itu.

Setelah dependensi dikompilasi, membuat `Bitcoin-Qt.app` mudah:

    make -f Makefile.osx RELEASE = 1

Running
-------

It's now available at `./bitcoind`, provided that you are still in the `src`
directory. We have to first create the RPC configuration file, though.

Run `./bitcoind` to get the filename where it should be put, or just try these
commands:

    echo -e "rpcuser=sifcoinrpc\nrpcpassword=$(xxd -l 16 -p /dev/urandom)" > "/Users/${USER}/Library/Application Support/Sifcoin/sifcoin.conf"
    chmod 600 "/Users/${USER}/Library/Application Support/Sifcoin/sifcoin.conf"

When next you run it, it will start downloading the blockchain, but it won't
output anything while it's doing this. This process may take several hours.

Other commands:

    ./bitcoind --help  # for a list of command-line options.
    ./bitcoind -daemon # to start the bitcoin daemon.
    ./bitcoind help    # When the daemon is running, to get a list of RPC commands

Lari
-------

Sekarang tersedia di `. / Bitcoind`, asalkan Anda masih berada di` src`
direktori. Kita harus terlebih dahulu membuat file konfigurasi RPC.

Jalankan `. / Bitcoind` untuk mendapatkan nama file yang harus diletakkan, atau coba saja
perintah:

     echo -e "rpcuser = sifcoinrpc \ nrpcpassword = $ (xxd -l 16 -p / dev / urandom)"> "/ Users / $ {USER} / Library / Application Support / Sifcoin / sifcoin.conf"
     chmod 600 "/ Users / $ {USER} / Perpustakaan / Dukungan Aplikasi / Sifcoin / sifcoin.conf"

Ketika selanjutnya Anda menjalankannya, ia akan mulai mendownload blockchainnya, tapi tidak akan
Keluarkan apapun saat melakukan ini. Proses ini mungkin memakan waktu beberapa jam.
