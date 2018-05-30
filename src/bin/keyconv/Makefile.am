MAINTAINERCLEANFILES =	$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/../../lib/crypto \
				@CRYPTO_INCLUDES@

dist_man_MANS =			softhsm2-keyconv.1

bin_PROGRAMS =			softhsm2-keyconv

softhsm2_keyconv_SOURCES =	softhsm2-keyconv.cpp \
				base64.c
softhsm2_keyconv_LDADD =	@CRYPTO_LIBS@

# Compile with OpenSSL support
if WITH_OPENSSL
softhsm2_keyconv_SOURCES +=	softhsm2-keyconv-ossl.cpp \
				../../lib/crypto/OSSLComp.cpp
endif

# Compile with Botan support
if WITH_BOTAN
softhsm2_keyconv_SOURCES +=	softhsm2-keyconv-botan.cpp
endif

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h \
				$(srcdir)/*.cpp
