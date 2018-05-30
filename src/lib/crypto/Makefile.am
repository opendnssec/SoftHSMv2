MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../common \
				-I$(srcdir)/../data_mgr \
				-I$(srcdir)/../pkcs11 \
				@CRYPTO_INCLUDES@

noinst_LTLIBRARIES =		libsofthsm_crypto.la
libsofthsm_crypto_la_SOURCES =	AESKey.cpp \
				AsymmetricAlgorithm.cpp \
				AsymmetricKeyPair.cpp \
				CryptoFactory.cpp \
				DerUtil.cpp \
				DESKey.cpp \
				DHParameters.cpp \
				DHPublicKey.cpp \
				DHPrivateKey.cpp \
				DSAParameters.cpp \
				DSAPublicKey.cpp \
				DSAPrivateKey.cpp \
				ECParameters.cpp \
				ECPublicKey.cpp \
				ECPrivateKey.cpp \
				EDPublicKey.cpp \
				EDPrivateKey.cpp \
				GOSTPublicKey.cpp \
				GOSTPrivateKey.cpp \
				HashAlgorithm.cpp \
				MacAlgorithm.cpp \
				RSAParameters.cpp \
				RSAPrivateKey.cpp \
				RSAPublicKey.cpp \
				SymmetricAlgorithm.cpp \
				SymmetricKey.cpp
libsofthsm_crypto_la_LIBADD =	@CRYPTO_LIBS@

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h \
				$(srcdir)/*.cpp

# Compile with support of OpenSSL
if WITH_OPENSSL
libsofthsm_crypto_la_SOURCES +=	OSSLAES.cpp \
				OSSLComp.cpp \
				OSSLCryptoFactory.cpp \
				OSSLDES.cpp \
				OSSLDH.cpp \
				OSSLDHKeyPair.cpp \
				OSSLDHPrivateKey.cpp \
				OSSLDHPublicKey.cpp \
				OSSLDSA.cpp \
				OSSLDSAKeyPair.cpp \
				OSSLDSAPrivateKey.cpp \
				OSSLDSAPublicKey.cpp \
				OSSLECDH.cpp \
				OSSLECDSA.cpp \
				OSSLECKeyPair.cpp \
				OSSLECPrivateKey.cpp \
				OSSLECPublicKey.cpp \
				OSSLEDDSA.cpp \
				OSSLEDKeyPair.cpp \
				OSSLEDPrivateKey.cpp \
				OSSLEDPublicKey.cpp \
				OSSLEVPHashAlgorithm.cpp \
				OSSLEVPMacAlgorithm.cpp \
				OSSLEVPCMacAlgorithm.cpp \
				OSSLEVPSymmetricAlgorithm.cpp \
				OSSLGOST.cpp \
				OSSLGOSTKeyPair.cpp \
				OSSLGOSTPrivateKey.cpp \
				OSSLGOSTPublicKey.cpp \
				OSSLGOSTR3411.cpp \
				OSSLCMAC.cpp \
				OSSLHMAC.cpp \
				OSSLMD5.cpp \
				OSSLRNG.cpp \
				OSSLRSA.cpp \
				OSSLRSAKeyPair.cpp \
				OSSLRSAPrivateKey.cpp \
				OSSLRSAPublicKey.cpp \
				OSSLSHA1.cpp \
				OSSLSHA224.cpp \
				OSSLSHA256.cpp \
				OSSLSHA384.cpp \
				OSSLSHA512.cpp \
				OSSLUtil.cpp
endif

# Compile with support of Botan
if WITH_BOTAN
libsofthsm_crypto_la_SOURCES +=	BotanAES.cpp \
				BotanCryptoFactory.cpp \
				BotanDES.cpp \
				BotanDH.cpp \
				BotanDHKeyPair.cpp \
				BotanDHPrivateKey.cpp \
				BotanDHPublicKey.cpp \
				BotanDSA.cpp \
				BotanDSAKeyPair.cpp \
				BotanDSAPrivateKey.cpp \
				BotanDSAPublicKey.cpp \
				BotanECDH.cpp \
				BotanECDHKeyPair.cpp \
				BotanECDHPrivateKey.cpp \
				BotanECDHPublicKey.cpp \
				BotanECDSA.cpp \
				BotanECDSAKeyPair.cpp \
				BotanECDSAPrivateKey.cpp \
				BotanECDSAPublicKey.cpp \
				BotanEDDSA.cpp \
				BotanEDKeyPair.cpp \
				BotanEDPrivateKey.cpp \
				BotanEDPublicKey.cpp \
				BotanGOST.cpp \
				BotanGOSTKeyPair.cpp \
				BotanGOSTPrivateKey.cpp \
				BotanGOSTPublicKey.cpp \
				BotanGOSTR3411.cpp \
				BotanHashAlgorithm.cpp \
				BotanMAC.cpp \
				BotanMacAlgorithm.cpp \
				BotanMD5.cpp \
				BotanRNG.cpp \
				BotanRSA.cpp \
				BotanRSAKeyPair.cpp \
				BotanRSAPrivateKey.cpp \
				BotanRSAPublicKey.cpp \
				BotanSHA1.cpp \
				BotanSHA224.cpp \
				BotanSHA256.cpp \
				BotanSHA384.cpp \
				BotanSHA512.cpp \
				BotanSymmetricAlgorithm.cpp \
				BotanUtil.cpp \
				Botan_ecb.cpp
endif
