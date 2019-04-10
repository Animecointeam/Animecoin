Animecoin 0.9.1
====================

Intro
---------------------
Animecoin is a free open source peer-to-peer electronic cash system that is completely decentralized, without the need for a central server or trusted parties. Users hold the crypto keys to their own money and transact directly with each other, with the help of a P2P network to check for double-spending.

Coin features
---------------------
- Unique algo (derived from quark).
- Fast, cheap transactions, blocks generated every 30 sec on average.
- No premine.

Upgrading
---------------------
Upgrading to 0.9 is meant to be fully transparent for both database and network. You may just run the new release with the old data directory.

Downgrading
---------------------
However, if you decide to switch back to 0.8 release for any reason, you might get a blockchain validation error when starting the old client (due to 'pruned outputs' being omitted from the index of unspent transaction outputs). Running the old client with the -reindex option will rebuild the chainstate data structures and fix this the problem.
Also, the first time you run a 0.8 release on a 0.9 wallet it will rescan the blockchain for missing spent coins, which may take a long time.

What's new in 0.9.1
---------------------
- The client is now OpenSSL-1.1 compatible (included in win32 build). Also compatible with the newer Boost and miniupnpc releases!
- Coin Control Features available.
- Lots of modern RPC commands available, including getnetworkhashps.
- A commandline executable split into the separate animecoind and animecoin-cli.
- Updated the database code.
- The transaction creation is no longer limited to 159 inputs (should resolve the 1272 coin sending limit for solominers).
- Improved wallet loading and rescanning time.
- The client will now check for possible network forking at startup and issue a warning if needed.
- Added BIP 0070 payment requests support, while keeping the old receiving addresses tab in place for convenience.
- You may now choose the data directory on the first run or with -choosedatadir option.
- Network traffic graph.
- New options, make sure to review them!

Building from source
---------------------
You may use either way to build the Qt client:
1. animecoin-qt.pro for qmake / Qt Creator. Simply adjust the library paths and prefixes if needed and build.
2. Autotools for commandline (MSYS shell in Windows case):
 - ./autogen.sh
 - ./configure (with any options necessary)
 - make (use e.g. make -j8 for utilizing 8 CPU cores to speed up the build process)

You may want to use the strip utility to reduce the size of resulting executables.

Required libraries
---------------------
- Boost
- OpenSSL
- Berkeley DB
- protobuf (since Animecoin 0.9)
- Qt (optional if you don't need the GUI client)
- miniupnpc (optional)
- qrencode (optional)

Berkeley DB notes
---------------------
By default, cryptocurrency wallets use Berkeley DB 4.8 for portability.
You may, however, use a more recent version (specifying the path and suffix in the .pro file, or passing --with-incompatible-bdb to ./configure).

IF YOU BUILD YOUR CLIENT WITH DB OTHER THAN 4.8 YOUR WALLET.DAT FILE WILL NOT BE PORTABLE.

If you wish to convert your wallet.dat between versions, you'll need the BerkDB tools of both versions available.

For example: db6.3_dump wallet.dat | db4.8_load wallet.dat.new

Other release notes
---------------------
- Translations need people to work upon.
- Regression test network code (like testnet, but special) was added following the mainstream Bitcoin client, this remains untested so far.


License
---------------------
Copyright (c) 2009-2019 Bitcoin Developers
Copyright (c) 2014-2019 Animecoin Developers

Distributed under the MIT/X11 software license, see the accompanying file COPYING or http://opensource.org/licenses/MIT.
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](http://www.openssl.org/). This product includes cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), UPnP software written by Thomas Bernard and sphlib 3.0 by Thomas Pornin.



