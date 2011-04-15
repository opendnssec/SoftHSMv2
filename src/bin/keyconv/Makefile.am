# $Id$

MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS =			@CRYPTO_INCLUDES@

dist_man_MANS =			softhsm-keyconv.1

bin_PROGRAMS =			softhsm-keyconv

softhsm_keyconv_SOURCES =	softhsm-keyconv.cpp \
				base64.c
softhsm_keyconv_LDADD =		@CRYPTO_LIBS@

# Compile with OpenSSL support
if WITH_OPENSSL
softhsm_keyconv_SOURCES +=	softhsm-keyconv-ossl.cpp
endif

# Compile with Botan support
if WITH_BOTAN
softhsm_keyconv_SOURCES +=	softhsm-keyconv-botan.cpp
endif

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/*.cpp
