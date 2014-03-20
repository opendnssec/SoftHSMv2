MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../../lib/cryptoki_compat \
			-I$(srcdir)/../common \
			@CRYPTO_INCLUDES@

dist_man_MANS =		softhsm2-util.1

bin_PROGRAMS =		softhsm2-util

softhsm2_util_SOURCES =	softhsm2-util.cpp \
			../common/getpw.cpp \
			../common/library.cpp
softhsm2_util_LDADD =	@CRYPTO_LIBS@

# Compile with support of OpenSSL
if WITH_OPENSSL
softhsm2_util_SOURCES +=	softhsm2-util-ossl.cpp
endif

# Compile with support of Botan
if WITH_BOTAN
softhsm2_util_SOURCES +=	softhsm2-util-botan.cpp
endif

EXTRA_DIST =		$(srcdir)/*.h \
			$(srcdir)/*.cpp
