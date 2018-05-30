MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../common \
				-I$(srcdir)/../pkcs11 \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		p11test

AUTOMAKE_OPTIONS =		subdir-objects

p11test_SOURCES =		p11test.cpp \
				SymmetricAlgorithmTests.cpp \
				DigestTests.cpp \
				InitTests.cpp \
				InfoTests.cpp \
				RandomTests.cpp \
				SessionTests.cpp \
				TokenTests.cpp \
				UserTests.cpp \
				ObjectTests.cpp \
				DeriveTests.cpp \
				SignVerifyTests.cpp \
				AsymEncryptDecryptTests.cpp \
				AsymWrapUnwrapTests.cpp \
				TestsBase.cpp \
				TestsNoPINInitBase.cpp \
				../common/log.cpp \
				../common/osmutex.cpp

p11test_LDADD =			../libsofthsm2.la

p11test_LDFLAGS = 		@CRYPTO_LIBS@ @CPPUNIT_LIBS@ -no-install -pthread -static

TESTS = 			p11test

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h \
				$(srcdir)/softhsm2-alt.conf.win32 \
				$(srcdir)/softhsm2.conf.win32 \
				$(srcdir)/tokens/dummy.in
