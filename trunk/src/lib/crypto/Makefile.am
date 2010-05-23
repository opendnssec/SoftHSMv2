# $Id: Makefile.am 32 2010-03-05 13:10:43Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/../data_mgr \
				@CRYPTO_INCLUDES@

noinst_LTLIBRARIES =		libsofthsm_crypto.la
libsofthsm_crypto_la_SOURCES =	AsymmetricAlgorithm.cpp \
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
libsofthsm_crypto_la_LIBADD =	@CRYPTO_LIBS@

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/*.h $(srcdir)/*.cpp

# Compile with support of OpenSSL
if WITH_OPENSSL
libsofthsm_crypto_la_SOURCES +=	OSSLAES.cpp \
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
endif

# Compile with support of Botan
if WITH_BOTAN
libsofthsm_crypto_la_SOURCES +=	BotanAES.cpp \
				BotanCryptoFactory.cpp \
				BotanHashAlgorithm.cpp \
				BotanMD5.cpp \
				BotanRNG.cpp \
				BotanSHA1.cpp \
				BotanSHA256.cpp \
				BotanSHA512.cpp \
				BotanSymmetricAlgorithm.cpp
endif
