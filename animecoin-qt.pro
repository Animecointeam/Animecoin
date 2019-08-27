TEMPLATE = app
TARGET = animecoin-qt
macx:TARGET = "Animecoin-Qt"
VERSION = 0.10.0
INCLUDEPATH += src src/qt
QT += network printsupport
DEFINES += QT_GUI BOOST_THREAD_USE_LIB HAVE_WORKING_BOOST_SLEEP_FOR
DEFINES += ENABLE_WALLET
CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static
#CONFIG += openssl
CONFIG += c++14
CONFIG += object_parallel_to_source

greaterThan(QT_MAJOR_VERSION, 4) {
     QT += widgets
     DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0
 }

contains(USE_BIP70, 1) {
    message(Building with deprecated BIP70 support)
    PROTO_DIR = src/qt
    include(share/qt/protobuf.pri)
    PROTOS = src/qt/paymentrequest.proto
    DEFINES += ENABLE_BIP70
    HEADERS += src/qt/paymentrequestplus.h
    SOURCES += src/qt/paymentrequestplus.cpp
}
else
{
    DEFINES += DISABLE_BIP70
}

contains(USE_ZMQ, 1) {
    message(Building with ZMQ support)
    DEFINES += ENABLE_ZMQ
    HEADERS += src/zmq/zmqabstractnotifier.h \
    src/zmq/zmqconfig.h \
    src/zmq/zmqnotificationinterface.h \
    src/zmq/zmqpublishnotifier.h
    SOURCES += src/zmq/zmqabstractnotifier.cpp \
    src/zmq/zmqnotificationinterface.cpp \
    src/zmq/zmqpublishnotifier.cpp
    LIBS += -lzmq
}
else
{
    DEFINES += DISABLE_ZMQ
}

QMAKE_CFLAGS+="-O2 -march=native -ftree-vectorize -floop-interchange -ftree-loop-distribution -floop-strip-mine -floop-block"
QMAKE_CXXFLAGS+="-O2 -march=native -ftree-vectorize -floop-interchange -ftree-loop-distribution -floop-strip-mine -floop-block -Wno-deprecated-copy"
#QMAKE_LFLAGS+="-flto"

# for boost 1.37, add -mt to the boost libraries
# use: qmake BOOST_LIB_SUFFIX=-mt
# for boost thread win32 with _win32 sufix
# use: BOOST_THREAD_LIB_SUFFIX=_win32-...
# or when linking against a specific BerkelyDB version: BDB_LIB_SUFFIX=-4.8

# Dependency library locations can be customized with:
#    BOOST_INCLUDE_PATH, BOOST_LIB_PATH, BDB_INCLUDE_PATH,
#    BDB_LIB_PATH, OPENSSL_INCLUDE_PATH and OPENSSL_LIB_PATH respectively

BDB_INCLUDE_PATH = /usr/include/db4.8
BDB_LIB_SUFFIX=-4.8

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

# use: qmake "RELEASE=1"
contains(RELEASE, 1) {
    # Mac: compile for maximum compatibility (10.5, 32-bit)
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.5 -arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_CFLAGS += -mmacosx-version-min=10.5 -arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk
    macx:QMAKE_OBJECTIVE_CFLAGS += -mmacosx-version-min=10.5 -arch i386 -isysroot /Developer/SDKs/MacOSX10.5.sdk

    !win32:!macx {
        # Linux: static link and extra security (see: https://wiki.debian.org/Hardening)
        LIBS += -Wl,-Bstatic -Wl,-z,relro -Wl,-z,now
    }
	win32: {
		# Windows: static link
		LIBS += -Wl,-Bstatic
	}
}

# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
QMAKE_CXXFLAGS *= -fstack-protector-all
QMAKE_LFLAGS *= -fstack-protector-all
# This may fail with prehistoric MinGW versions.

# for extra security (see: https://wiki.debian.org/Hardening): this flag is GCC compiler-specific
QMAKE_CXXFLAGS *= -D_FORTIFY_SOURCE=2
# for extra security on Windows: enable ASLR and DEP via GCC linker flags
win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat
# on Windows: enable GCC large address aware linker flag
#win32:QMAKE_LFLAGS *= -Wl,--large-address-aware -static
win32:QMAKE_LFLAGS *= -static
# i686-w64-mingw32
win32:QMAKE_CXXFLAGS *= -static-libgcc -static-libstdc++
win32:QMAKE_LFLAGS *= -static-libgcc -static-libstdc++

# platform specific defaults, if not overridden on command line
isEmpty(BOOST_LIB_SUFFIX) {
	macx:BOOST_LIB_SUFFIX = -mt
	win32: BOOST_LIB_SUFFIX=-mgw73-mt-1_65
}

isEmpty(BOOST_THREAD_LIB_SUFFIX) {
	BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}

isEmpty(BDB_LIB_PATH) {
	macx:BDB_LIB_PATH = /opt/local/lib/db48
	win32:BDB_LIB_PATH = F:\db-4.8.30\build_unix\.libs
}

isEmpty(BDB_LIB_SUFFIX) {
	macx:BDB_LIB_SUFFIX = -4.8
	win32:BDB_LIB_SUFFIX = -4.8
}

isEmpty(BDB_INCLUDE_PATH) {
	macx:BDB_INCLUDE_PATH = /opt/local/include/db48
	win32:BDB_INCLUDE_PATH = F:\db-4.8.30\build_unix
}

isEmpty(BOOST_LIB_PATH) {
	macx:BOOST_LIB_PATH = /opt/local/lib
	win32:BOOST_LIB_PATH = F:\libs\boost_1_65_0\stage\lib
}

isEmpty(BOOST_INCLUDE_PATH) {
	macx:BOOST_INCLUDE_PATH = /opt/local/include
	win32:BOOST_INCLUDE_PATH = F:\libs\boost_1_65_0
}

isEmpty(OPENSSL_INCLUDE_PATH) {
	win32: OPENSSL_INCLUDE_PATH = F:\openssl-1.1.1-win64-mingw\include
}

isEmpty(OPENSSL_LIB_PATH) {
	win32: OPENSSL_LIB_PATH = F:\openssl-1.1.1-win64-mingw\lib
}

isEmpty(MINIUPNPC_INCLUDE_PATH) {
	win32:MINIUPNPC_INCLUDE_PATH = F:\libs
}

isEmpty(MINIUPNPC_LIB_PATH) {
	win32: MINIUPNPC_LIB_PATH = F:\libs\miniupnpc
}

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
	message(Building with QRCode support)
	DEFINES += USE_QRCODE
	LIBS += -lqrencode
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    win32:LIBS += -liphlpapi
}

# use: qmake "USE_DBUS=1"
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}

# use: qmake "USE_IPV6=1" ( enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(BITCOIN_NEED_QT_PLUGINS, 1) {
    DEFINES += BITCOIN_NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

INCLUDEPATH += src/leveldb/include src/leveldb/helpers src/leveldb/helpers/memenv
LIBS += $$PWD/src/leveldb/out-static/libleveldb.a $$PWD/src/leveldb/out-static/libmemenv.a
!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"
} else {
    # make an educated guess about what the ranlib command is called
    isEmpty(QMAKE_RANLIB) {
        QMAKE_RANLIB = $$replace(QMAKE_STRIP, strip, ranlib)
    }
    LIBS += -lshlwapi
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX TARGET_OS=OS_WINDOWS_CROSSCOMPILE $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"
# && $$QMAKE_RANLIB $$PWD/src/leveldb/libleveldb.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libmemenv.a
}
genleveldb.target = src/leveldb/out-static/libleveldb.a
genleveldb.depends = FORCE
PRE_TARGETDEPS += src/leveldb/out-static/libleveldb.a
QMAKE_EXTRA_TARGETS += genleveldb
# Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
QMAKE_CLEAN += src/leveldb/out-static/libleveldb.a; cd $$PWD/src/leveldb ; $(MAKE) clean

#Build Secp256k1
!win32 {
INCLUDEPATH += src/secp256k1/include
LIBS += $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o
	# we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    gensecp256k1.commands = cd $$PWD/src/secp256k1 && ./autogen.sh && ./configure --with-bignum=no --enable-module-recovery && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"
    gensecp256k1.target = $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o
	gensecp256k1.depends = FORCE
    PRE_TARGETDEPS += $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o
	QMAKE_EXTRA_TARGETS += gensecp256k1
	# Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
    QMAKE_CLEAN += $$PWD/src/secp256k1/src/libsecp256k1_la-secp256k1.o; cd $$PWD/src/secp256k1; $(MAKE) clean
} else {
	isEmpty(SECP256K1_LIB_PATH) {
		windows:SECP256K1_LIB_PATH=src/secp256k1win2/
	}
	isEmpty(SECP256K1_INCLUDE_PATH) {
		windows:SECP256K1_INCLUDE_PATH=src/secp256k1win2/include
	}
}

#Build univalue
INCLUDEPATH += src/univalue/include
LIBS += $$PWD/src/univalue/lib/libunivalue_la-univalue.o $$PWD/src/univalue/lib/libunivalue_la-univalue_read.o $$PWD/src/univalue/lib/libunivalue_la-univalue_write.o
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genunivalue.commands = cd $$PWD/src/univalue && ./autogen.sh && ./configure && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\"
    genunivalue.target = $$PWD/src/univalue/lib/libunivalue_la-univalue.o $$PWD/src/univalue/lib/libunivalue_la-univalue_read.o $$PWD/src/univalue/lib/libunivalue_la-univalue_write.o
    genunivalue.depends = FORCE
    PRE_TARGETDEPS += $$PWD/src/univalue/lib/libunivalue_la-univalue.o $$PWD/src/univalue/lib/libunivalue_la-univalue_read.o $$PWD/src/univalue/lib/libunivalue_la-univalue_write.o
    QMAKE_EXTRA_TARGETS += genunivalue
    # Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
    QMAKE_CLEAN += $$PWD/src/univalue/lib/libunivalue_la-univalue.o $$PWD/src/univalue/lib/libunivalue_la-univalue_read.o $$PWD/src/univalue/lib/libunivalue_la-univalue_write.o; cd $$PWD/src/univalue; $(MAKE) clean

# regenerate src/build.h
!win32:contains(USE_BUILD_INFO, 1) {
    message(Building with build info)
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter -Wstack-protector

# Input
DEPENDPATH += src src/qt
HEADERS += src/qt/bitcoingui.h \
    src/auxiliaryblockrequest.h \
    src/crypto/aes.h \
    src/indirectmap.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/editaddressdialog.h \
    src/qt/bitcoinaddressvalidator.h \
    src/alert.h \
    src/addrman.h \
    src/base58.h \
    src/checkpoints.h \
    src/compat.h \
    src/rpc/register.h \
    src/sync.h \
    src/threadinterrupt.h \
    src/util.h \
    src/hash.h \
    src/uint256.h \
    src/serialize.h \
    src/main.h \
    src/net.h \
    src/key.h \
    src/init.h \
    src/bloom.h \
    src/checkqueue.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/bitcoinamountfield.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/qt/walletview.h \
    src/qt/walletframe.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/bitcoinunits.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/paymentserver.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/version.h \
    src/netbase.h \
    src/clientversion.h \
	src/coincontrol.h \
    src/txdb.h \
    src/threadsafety.h \
    src/limitedmap.h \
    src/qt/splashscreen.h \
    src/hashblock.h \
    src/coincontrol.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/chainparams.h \
    src/miner.h \
    src/noui.h \
    src/coins.h \
    src/txmempool.h \
    src/tinyformat.h \
    src/qt/intro.h \
    src/qt/utilitydialog.h \
    src/qt/winshutdownmonitor.h \
    src/qt/openuridialog.h \
    src/qt/receivecoinsdialog.h \
    src/qt/walletmodeltransaction.h \
    src/qt/recentrequeststablemodel.h \
    src/qt/trafficgraphwidget.h \
	src/qt/receiverequestdialog.h \
    src/qt/verticallabel.h \
    src/crypto/sha512.h \
    src/crypto/sph_blake.h \
    src/crypto/sph_bmw.h \
    src/crypto/sph_groestl.h \
    src/crypto/sph_jh.h \
    src/crypto/sph_types.h \
    src/crypto/sph_keccak.h \
    src/crypto/sph_skein.h \
    src/crypto/common.h \
    src/crypto/hmac_sha256.h \
    src/crypto/hmac_sha512.h \
    src/crypto/rfc6979_hmac_sha256.h \
    src/crypto/ripemd160.h \
    src/crypto/sha1.h \
    src/crypto/sha256.h \
    src/streams.h \
    src/random.h \
    src/timedata.h \
    src/utilstrencodings.h \
    src/core_io.h \
    src/amount.h \
    src/pubkey.h \
    src/script/bitcoinconsensus.h \
    src/script/interpreter.h \
    src/script/script.h \
    src/script/script_error.h \
    src/script/sigcache.h \
    src/script/sign.h \
    src/script/standard.h \
    src/primitives/block.h \
    src/primitives/transaction.h \
    src/chain.h \
    src/pow.h \
    src/chainparamsbase.h \
    src/chainparamsseeds.h \
    src/compressor.h \
    src/config/bitcoin-config.h \
    src/merkleblock.h \
    src/undo.h \
    src/qt/networkstyle.h \
    src/qt/peertablemodel.h \
    src/utilmoneystr.h \
    src/utiltime.h \
    src/qt/askmultisigdialog.h \
    src/qt/newpubkeydialog.h \
    src/scheduler.h \
    src/consensus/params.h \
    src/arith_uint256.h \
    src/wallet/db.h \
    src/wallet/wallet.h \
    src/wallet/walletdb.h \
    src/consensus/consensus.h \
    src/consensus/validation.h \
    src/reverselock.h \
    src/policy/fees.h \
    src/wallet/crypter.h \
    src/support/cleanse.h \
    src/policy/policy.h \
    src/validationinterface.h \
    src/reverse_iterator.h \
    src/torcontrol.h \
    src/memusage.h \
    src/core_memusage.h \
    src/httprpc.h \
    src/httpserver.h \
    src/consensus/merkle.h \
    src/prevector.h \
    src/cuckoocache.h \
    src/support/allocators/secure.h \
    src/support/allocators/zeroafterfree.h \
    src/qt/bantablemodel.h \
    src/dbwrapper.h \
    src/wallet/rpcwallet.h \
    src/rpc/client.h \
    src/rpc/protocol.h \
    src/rpc/server.h \
    src/crypto/ctaes/ctaes.h \
    src/support/lockedpool.h \
    src/compat/byteswap.h \
    src/compat/endian.h \
    src/blockencodings.h \
    src/addrdb.h \
    src/netaddress.h \
    src/netmessagemaker.h \
    src/script/ismine.h \
    src/policy/rbf.h

SOURCES += src/qt/bitcoin.cpp \
    src/auxiliaryblockrequest.cpp \
    src/crypto/aes.cpp \
    #src/crypto/ctaes/bench.c \
    src/crypto/ctaes/ctaes.c \
    #src/crypto/ctaes/test.c \
    src/qt/bitcoingui.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/alert.cpp \
    src/sync.cpp \
    src/threadinterrupt.cpp \
    src/util.cpp \
    src/hash.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/main.cpp \
    src/init.cpp \
    src/net.cpp \
    src/bloom.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/qt/clientmodel.cpp \
	src/qt/coincontroldialog.cpp \
	src/qt/coincontroltreewidget.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/bitcoinstrings.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/qt/walletview.cpp \
    src/qt/walletframe.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/paymentserver.cpp \
    src/qt/rpcconsole.cpp \
    src/noui.cpp \
    src/txdb.cpp \
    src/qt/splashscreen.cpp \
    src/base58.cpp \
    src/chainparams.cpp \
    src/miner.cpp \
    src/coins.cpp \
    src/qt/intro.cpp \
    src/qt/utilitydialog.cpp \
    src/qt/winshutdownmonitor.cpp \
    src/qt/openuridialog.cpp \
    src/qt/receivecoinsdialog.cpp \
    src/qt/walletmodeltransaction.cpp \
    src/qt/recentrequeststablemodel.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/receiverequestdialog.cpp \
    src/qt/verticallabel.cpp \
    src/crypto/sha512.cpp \
    src/crypto/skein.c \
    src/crypto/blake.c \
    src/crypto/bmw.c \
    src/crypto/groestl.c \
    src/crypto/hmac_sha256.cpp \
    src/crypto/hmac_sha512.cpp \
    src/crypto/jh.c \
    src/crypto/keccak.c \
    src/crypto/rfc6979_hmac_sha256.cpp \
    src/crypto/ripemd160.cpp \
    src/crypto/sha1.cpp \
    src/crypto/sha256.cpp \
    src/random.cpp \
    src/timedata.cpp \
    src/utilstrencodings.cpp \
    src/core_read.cpp \
    src/core_write.cpp \
    src/amount.cpp \
    src/pubkey.cpp \
    src/script/bitcoinconsensus.cpp \
    src/script/interpreter.cpp \
    src/script/script.cpp \
    src/script/script_error.cpp \
    src/script/sigcache.cpp \
    src/script/sign.cpp \
    src/script/standard.cpp \
    src/primitives/block.cpp \
    src/primitives/transaction.cpp \
    src/chain.cpp \
    src/pow.cpp \
    src/chainparamsbase.cpp \
    src/clientversion.cpp \
    src/compressor.cpp \
    src/merkleblock.cpp \
    src/qt/networkstyle.cpp \
    src/qt/peertablemodel.cpp \
    src/rest.cpp \
    src/uint256.cpp \
    src/utilmoneystr.cpp \
    src/utiltime.cpp \
    src/compat/glibc_sanity.cpp \
    src/compat/glibcxx_sanity.cpp \
    src/compat/strnlen.cpp \
    src/qt/askmultisigdialog.cpp \
    src/qt/newpubkeydialog.cpp \
    src/scheduler.cpp \
    src/wallet/db.cpp \
    src/wallet/rpcdump.cpp \
    src/wallet/rpcwallet.cpp \
    src/wallet/wallet.cpp \
    src/wallet/walletdb.cpp \
    src/policy/fees.cpp \
    src/txmempool.cpp \
    src/wallet/crypter.cpp \
    src/support/cleanse.cpp \
    src/validationinterface.cpp \
    src/torcontrol.cpp \
    src/httprpc.cpp \
    src/httpserver.cpp \
    src/policy/policy.cpp \
    src/consensus/merkle.cpp \
    src/arith_uint256.cpp \
    src/qt/bantablemodel.cpp \
    src/dbwrapper.cpp \
    src/rpc/blockchain.cpp \
    src/rpc/client.cpp \
    src/rpc/mining.cpp \
    src/rpc/misc.cpp \
    src/rpc/net.cpp \
    src/rpc/protocol.cpp \
    src/rpc/rawtransaction.cpp \
    src/rpc/server.cpp \
    src/support/lockedpool.cpp \
    src/blockencodings.cpp \
    src/addrdb.cpp \
    src/netaddress.cpp \
    src/ui_interface.cpp \
    src/script/ismine.cpp \
    src/policy/rbf.cpp

RESOURCES += src/qt/bitcoin.qrc \
    src/qt/bitcoin_locale.qrc

FORMS += src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/aboutdialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
	src/qt/forms/coincontroldialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/receivecoinsdialog.ui \
    src/qt/forms/openuridialog.ui \
    src/qt/forms/intro.ui \
    src/qt/forms/helpmessagedialog.ui \
    src/qt/forms/receiverequestdialog.ui \
    src/qt/forms/paperwalletdialog.ui \
    src/qt/forms/askmultisigdialog.ui \
    src/qt/forms/newpubkeydialog.ui

contains(USE_QRCODE, 1) {
HEADERS +=
SOURCES +=
FORMS +=
}

contains(BITCOIN_QT_TEST, 1) {
SOURCES += src/qt/test/test_main.cpp \
    src/qt/test/uritests.cpp
HEADERS += src/qt/test/uritests.h
DEPENDPATH += src/qt/test
QT += testlib
TARGET = bitcoin-qt_test
DEFINES += BITCOIN_QT_TEST
  macx: CONFIG -= app_bundle
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/bitcoin.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

isEmpty(QMAKE_LRELEASE) {
    win32:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
    else:QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += README.md \
    doc/*.rst \
    doc/*.txt \
    doc/*.md \
    src/qt/res/bitcoin-qt.rc \
    src/test/*.cpp \
    src/test/*.h \
    src/qt/test/*.cpp \
    src/qt/test/*.h

win32:DEFINES += WIN32
win32:RC_FILE = src/qt/res/bitcoin-qt.rc

win32:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

!win32:!macx {
    DEFINES += LINUX
    LIBS += -lrt
    # _FILE_OFFSET_BITS=64 lets 32-bit fopen transparently support large files.
    DEFINES += _FILE_OFFSET_BITS=64
}

macx:HEADERS += src/qt/macdockiconhandler.h \
	src/qt/macnotificationhandler.h

macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm \
	src/qt/macnotificationhandler.mm

macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/bitcoin.icns
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread
macx:QMAKE_INFO_PLIST = share/qt/Info.plist

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH
LIBS += $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,)
LIBS += -lcrypto -lz -ldb_cxx$$BDB_LIB_SUFFIX -lprotobuf -levent -levent_pthreads
# -lgdi32 has to happen after -lcrypto (see  #681)
win32:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
!windows: {
    #LIBS += -lgmp
} else {
	INCLUDEPATH += $$SECP256K1_INCLUDE_PATH
    LIBS += -L/usr/local/lib -L/usr/lib
# -lsecp256k1
}
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX -lboost_chrono$$BOOST_LIB_SUFFIX
#win32:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX
#macx:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX

contains(RELEASE, 1) {
    !win32:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}

!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt -ldl
}

system($$QMAKE_LRELEASE -silent $$TRANSLATIONS)