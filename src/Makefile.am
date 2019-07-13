DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/univalue/include

LIBBITCOIN_SERVER=libanimecoin_server.a
LIBBITCOIN_COMMON=libanimecoin_common.a
LIBBITCOIN_CONSENSUS=libanimecoin_consensus.a
LIBBITCOIN_CLI=libanimecoin_cli.a
LIBBITCOIN_UTIL=libanimecoin_util.a
LIBBITCOIN_CRYPTO=crypto/libanimecoin_crypto.a
LIBBITCOINQT=qt/libanimecoinqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBUNIVALUE=univalue/lib/libunivalue.la

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libanimecoin_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBBITCOINCONSENSUS=libanimecoinconsensus.la
endif
if ENABLE_WALLET
LIBBITCOIN_WALLET=libanimecoin_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)


$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $ univalue/
	
# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
$(LIBBITCOIN_CRYPTO) \
$(LIBBITCOIN_UTIL) \
$(LIBBITCOIN_COMMON) \
$(LIBBITCOIN_CONSENSUS) \
$(LIBBITCOIN_SERVER) \
$(LIBBITCOIN_CLI) \
$(LIBBITCOIN_WALLET) \
$(LIBBITCOIN_ZMQ)

lib_LTLIBRARIES = $(LIBBITCOINCONSENSUS)

bin_PROGRAMS =
TESTS =

if BUILD_BITCOIND
  bin_PROGRAMS += animecoind
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += animecoin-cli animecoin-tx
endif

.PHONY: FORCE
# animecoin core #
BITCOIN_CORE_H = \
  addrman.h \
  alert.h \
  arith_uint256.h \
  base58.h \
  bloom.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/params.h \
  core_io.h \
  core_memusage.h \
  crypto/sph_types.h \
  crypto/sph_blake.h \
  crypto/sph_groestl.h \
  crypto/sph_keccak.h \
  crypto/sph_bmw.h \
  crypto/sph_jh.h \
  crypto/sph_skein.h \
  wallet/db.h \
  hashblock.h \
  httprpc.h \
  httpserver.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  main.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  netbase.h \
  net.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  pow.h \
  protocol.h \
  primitives/block.h \
  random.h \
  reverse_iterator.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/register.h \
  rpc/server.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validationinterface.h \
  wallet/crypter.h \
  wallet/rpcwallet.h \
  wallet/walletdb.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h\
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libanimecoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between animecoind and animecoin-qt
libanimecoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libanimecoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_server_a_SOURCES = \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  main.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validationinterface.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_ZMQ
libanimecoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif

# wallet: shared between animecoind and animecoin-qt, but only linked
# when wallet enabled
libanimecoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libanimecoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_wallet_a_SOURCES = \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_libanimecoin_crypto_a_CFLAGS = -fPIC
crypto_libanimecoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES)
crypto_libanimecoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libanimecoin_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  crypto/hmac_sha256.cpp \
  crypto/rfc6979_hmac_sha256.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/common.h \
  crypto/sha256.h \
  crypto/sha512.h \
  crypto/hmac_sha256.h \
  crypto/rfc6979_hmac_sha256.h \
  crypto/hmac_sha512.h \
  crypto/sha1.h \
  crypto/ripemd160.h \
  crypto/blake.c \
  crypto/bmw.c \
  crypto/groestl.c \
  crypto/jh.c \
  crypto/keccak.c \
  crypto/skein.c \
  crypto/sph_types.h \
  crypto/sph_blake.h \
  crypto/sph_groestl.h \
  crypto/sph_keccak.h \
  crypto/sph_bmw.h \
  crypto/sph_jh.h \
  crypto/sph_skein.h

# consensus: shared between all executables that validate any consensus rules.
libanimecoin_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libanimecoin_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_consensus_a_SOURCES = \
  amount.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between animecoind, and animecoin-qt and non-server tools
libanimecoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libanimecoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_common_a_SOURCES = \
  amount.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  core_read.cpp \
  core_write.cpp \
  key.cpp \
  keystore.cpp \
  netbase.cpp \
  pow.cpp \
  primitives/block.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libanimecoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libanimecoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_util_a_SOURCES = \
  compat/strnlen.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  arith_uint256.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  support/lockedpool.cpp \
  sync.cpp \
  util.cpp \
  utilstrencodings.cpp \
  utilmoneystr.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H)

if GLIBC_BACK_COMPAT
libanimecoin_util_a_SOURCES += compat/glibc_compat.cpp
libanimecoin_util_a_SOURCES += compat/glibcxx_compat.cpp
endif

# cli: shared between animecoin-cli and animecoin-qt
libanimecoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libanimecoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libanimecoin_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)

nodist_libanimecoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# animecoind binary #
animecoind_SOURCES = bitcoind.cpp
animecoind_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
animecoind_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
animecoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
animecoind_SOURCES += bitcoind-res.rc
endif

animecoind_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

animecoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# animecoin-cli binary #
animecoin_cli_SOURCES = bitcoin-cli.cpp
animecoin_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
animecoin_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
animecoin_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
animecoin_cli_SOURCES += bitcoin-cli-res.rc
endif

animecoin_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO) \
  $(BOOST_LIBS) \
  $(SSL_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_LIBS)
#

# animecoin-tx binary #
animecoin_tx_SOURCES = bitcoin-tx.cpp
animecoin_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
animecoin_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
animecoin_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

animecoin_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSECP256K1) \
  $(BOOST_LIBS) \
  $(CRYPTO_LIBS) \
  $(EVENT_LIBS)
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libanimecoinconsensus_la_SOURCES = $(crypto_libanimecoin_crypto_a_SOURCES) $(libanimecoin_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libanimecoinconsensus_la_SOURCES += compat/glibc_compat.cpp
  libanimecoinconsensus_la_SOURCES += compat/glibcxx_compat.cpp
endif

libanimecoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libanimecoinconsensus_la_LIBADD = $(LIBSECP256K1)
libanimecoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libanimecoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno
CLEANFILES += $(EXTRA_LIBRARIES)

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb $(CTAES_DIST)

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

if ENABLE_BIP70
%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)
endif

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
