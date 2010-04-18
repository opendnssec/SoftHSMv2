# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/../data_mgr

noinst_LTLIBRARIES =		libcrypto.la
libcrypto_la_SOURCES =		AsymmetricAlgorithm.cpp \
				AsymmetricKeyPair.cpp \
				CryptoFactory.cpp \
				DESKey.cpp \
				DSAParameters.cpp \
				DSAPublicKey.cpp \
				DSAPrivateKey.cpp \
				HashAlgorithm.cpp \
				RSAParameters.cpp \
				RSAPrivateKey.cpp \
				RSAPublicKey.cpp \
				SymmetricAlgorithm.cpp \
				SymmetricKey.cpp
libcrypto_la_LIBADD =		-lcrypto

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/*.h $(srcdir)/*.cpp

# Compile with support of OpenSSL
if WITH_OPENSSL
libcrypto_la_SOURCES +=		OSSLAES.cpp \
				OSSLCryptoFactory.cpp \
				OSSLDES.cpp \
				OSSLDSA.cpp \
				OSSLDSAKeyPair.cpp \
				OSSLDSAPrivateKey.cpp \
				OSSLDSAPublicKey.cpp \
				OSSLEVPHashAlgorithm.cpp \
				OSSLEVPSymmetricAlgorithm.cpp \
				OSSLMD5.cpp \
				OSSLRNG.cpp \
				OSSLRSA.cpp \
				OSSLRSAKeyPair.cpp \
				OSSLRSAPrivateKey.cpp \
				OSSLRSAPublicKey.cpp \
				OSSLSHA1.cpp \
				OSSLSHA256.cpp \
				OSSLSHA512.cpp \
				OSSLUtil.cpp
libcrypto_la_LIBADD +=		-lcrypto
endif

# Compile with support of Botan
if WITH_BOTAN
libcrypto_la_SOURCES +=		BotanCryptoFactory.cpp
libcrypto_la_LIBADD +=		-lbotan
endif
