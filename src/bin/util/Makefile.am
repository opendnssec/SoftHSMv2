MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS =		-I$(srcdir)/../common \
			-I$(srcdir)/../../lib/ \
			-I$(srcdir)/../../lib/common \
			-I$(srcdir)/../../lib/crypto \
			-I$(srcdir)/../../lib/data_mgr \
			-I$(srcdir)/../../lib/object_store \
			-I$(srcdir)/../../lib/pkcs11 \
			@CRYPTO_INCLUDES@ \
			@SQLITE3_INCLUDES@

dist_man_MANS =		softhsm2-util.1

bin_PROGRAMS =		softhsm2-util

AUTOMAKE_OPTIONS =	subdir-objects

softhsm2_util_SOURCES =	softhsm2-util.cpp \
			../common/findslot.cpp \
			../common/getpw.cpp \
			../common/library.cpp

softhsm2_util_LDADD =	@CRYPTO_LIBS@ \
			@SQLITE3_LIBS@ \
			../../lib/libsofthsm_convarch.la

# Compile with support of OpenSSL
if WITH_OPENSSL
softhsm2_util_SOURCES +=	softhsm2-util-ossl.cpp \
				../../lib/crypto/OSSLComp.cpp
endif

# Compile with support of Botan
if WITH_BOTAN
softhsm2_util_SOURCES +=	softhsm2-util-botan.cpp
endif

EXTRA_DIST =		$(srcdir)/CMakeLists.txt \
			$(srcdir)/*.h \
			$(srcdir)/*.cpp
