# $Id$

MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/cryptoki_compat \
			-I$(srcdir)/../common \
			@CRYPTO_INCLUDES@

dist_man_MANS =		softhsm-util.1

bin_PROGRAMS =		softhsm-util

softhsm_util_SOURCES =	softhsm-util.cpp \
			../common/getpw.cpp \
			../common/library.cpp
softhsm_util_LDADD =	@CRYPTO_LIBS@

# Compile with support of OpenSSL
if WITH_OPENSSL
softhsm_util_SOURCES +=	softhsm-util-ossl.cpp
endif

# Compile with support of Botan
if WITH_BOTAN
softhsm_util_SOURCES +=	softhsm-util-botan.cpp
endif

EXTRA_DIST =		$(srcdir)/*.h \
			$(srcdir)/*.cpp
