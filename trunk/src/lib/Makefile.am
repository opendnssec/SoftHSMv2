# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-DWITH_OPENSSL
AM_CFLAGS = 			-DWITH_OPENSSL

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		Configuration.cpp \
				fatal.cpp \
				main.cpp \
				SoftHSM.cpp \
				osmutex.c \
				XMLConfigLoader.cpp \
				BotanCryptoFactory.cpp \
				ByteString.cpp \
				CryptoFactory.cpp \
				OSSLCryptoFactory.cpp \
				OSSLRNG.cpp \
				SecureMemoryRegistry.cpp \
				SymmetricAlgorithm.cpp \
				SymmetricKey.cpp \
				log.cpp
libsofthsm_la_LIBADD =		-lcrypto
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@

EXTRA_DIST =			$(srcdir)/*.h
