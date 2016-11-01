MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../cryptoki_compat \
				-I$(srcdir)/../common \
				`cppunit-config --cflags`

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
				../common/osmutex.cpp

p11test_LDADD =			../libsofthsm2.la 

p11test_LDFLAGS = 		@CRYPTO_LIBS@ -no-install `cppunit-config --libs` -pthread -static

TESTS = 			p11test

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/softhsm2-alt.conf.win32 \
				$(srcdir)/softhsm2.conf.win32 \
				$(srcdir)/tokens/dummy.in
