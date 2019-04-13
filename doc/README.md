Animecoin 0.9.1
====================

Copyright (c) 2009-2013 Bitcoin Developers
Copyright (c) 2009-2019 Animecoin Developers

Setup
---------------------
Animecoin is the original client and it builds the backbone of the network. However, it downloads and stores the entire history of Animecoin transactions (which is currently several GBs); depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more. Thankfully you only have to do this once. If you would like the process to go faster you can [download the blockchain directly](bootstrap.md).


Running
---------------------
The following are some helpful notes on how to run Animecoin on your native platform. 

### Unix

You need the Qt5 run-time libraries to run Animecoin-Qt. On Debian or Ubuntu:

	sudo apt-get install libqtgui5

Unpack the files into a directory and run:

- bin/32/animecoin-qt (GUI, 32-bit) or bin/32/animecoind (headless, 32-bit)
- bin/64/animecoin-qt (GUI, 64-bit) or bin/64/animecoind (headless, 64-bit)

Unpack the files into a directory and run:

- bin/32/animecoin-qt (GUI, 32-bit)
- bin/32/animecoind (headless, 32-bit)
- bin/64/animecoin-qt (GUI, 64-bit)
- bin/64/animecoind (headless, 64-bit)

See the documentation at the [Bitcoin Wiki](https://en.bitcoin.it/wiki/Main_Page)
for help and more information.



### Windows

Unpack the files into a directory, and then run animecoin-qt.exe.

### OSX

Drag Animecoin-Qt to your applications folder, and then run Animecoin-Qt.

### Need Help?

* See the documentation at the [Bitcoin Wiki](https://en.bitcoin.it/wiki/Main_Page)
for help and more information.
* Ask for help on the [BitcoinTalk](https://bitcointalk.org/) forums, in the [Technical Support board](https://bitcointalk.org/index.php?board=4.0).

Building
---------------------
The following are developer notes on how to build Animecoin on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [OSX Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-msw.md)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Tor Support](tor.md)

License
---------------------
Distributed under the [MIT/X11 software license](http://www.opensource.org/licenses/mit-license.php).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](http://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
